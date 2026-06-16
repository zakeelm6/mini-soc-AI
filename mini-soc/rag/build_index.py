#!/usr/bin/env python3
"""
build_index.py — Construit la base vectorielle ChromaDB depuis les PDFs SOC.
Usage : python build_index.py
"""
import os, sys, re, subprocess

DOCS_DIR    = os.path.join(os.path.dirname(__file__), "docs")
VECTORS_DIR = os.path.join(os.path.dirname(__file__), "vectors")
COLLECTION  = "soc_knowledge"
CHUNK_SIZE  = 500   # caractères par chunk
CHUNK_OVERLAP = 80

def extract_text_from_pdf(pdf_path: str) -> str:
    """Extrait le texte d'un PDF avec pdftotext."""
    try:
        result = subprocess.run(
            ["pdftotext", "-layout", pdf_path, "-"],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception as e:
        print(f"  [WARN] pdftotext échoué pour {pdf_path}: {e}")
        return ""

def clean_text(text: str) -> str:
    """Nettoie le texte extrait."""
    text = re.sub(r'\f', '\n\n', text)           # form feeds → paragraphes
    text = re.sub(r'[ \t]{3,}', '  ', text)      # espaces multiples
    text = re.sub(r'\n{4,}', '\n\n\n', text)     # lignes vides excessives
    text = re.sub(r'[^\x00-\x7FÀ-ɏ]', '', text)  # non-ASCII exotique
    return text.strip()

def chunk_text(text: str, source: str) -> list[dict]:
    """Découpe en chunks avec overlap."""
    chunks = []
    paragraphs = text.split('\n\n')
    current = ""
    chunk_id = 0
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        if len(current) + len(para) < CHUNK_SIZE:
            current += "\n\n" + para
        else:
            if current.strip():
                chunks.append({
                    "id":      f"{source}_{chunk_id:04d}",
                    "text":    current.strip(),
                    "source":  source,
                    "chunk":   chunk_id,
                })
                chunk_id += 1
                # Overlap : garder la fin du chunk précédent
                current = current[-CHUNK_OVERLAP:] + "\n\n" + para
            else:
                current = para
    if current.strip():
        chunks.append({
            "id":     f"{source}_{chunk_id:04d}",
            "text":   current.strip(),
            "source": source,
            "chunk":  chunk_id,
        })
    return chunks

def build_index():
    try:
        import chromadb
        from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
    except ImportError:
        print("ERROR: pip install chromadb")
        sys.exit(1)

    # Client ChromaDB persistant
    client = chromadb.PersistentClient(path=VECTORS_DIR)

    # Embedding via Ollama nomic-embed-text
    embed_fn = OllamaEmbeddingFunction(
        model_name="nomic-embed-text",
        url=f"{os.getenv('OLLAMA_URL','http://localhost:11434')}/api/embeddings"
    )

    # Recréer la collection proprement
    try:
        client.delete_collection(COLLECTION)
        print(f"Collection '{COLLECTION}' supprimée (rebuild)")
    except Exception:
        pass
    collection = client.create_collection(COLLECTION, embedding_function=embed_fn)

    # Parcourir les PDFs
    pdfs = sorted(f for f in os.listdir(DOCS_DIR) if f.endswith(".pdf"))
    if not pdfs:
        print(f"Aucun PDF trouvé dans {DOCS_DIR}")
        sys.exit(1)

    total_chunks = 0
    for pdf_file in pdfs:
        pdf_path = os.path.join(DOCS_DIR, pdf_file)
        source   = pdf_file.replace(".pdf", "")
        print(f"\n[{source}]")

        raw   = extract_text_from_pdf(pdf_path)
        text  = clean_text(raw)
        if not text:
            print("  → Texte vide, ignoré")
            continue

        chunks = chunk_text(text, source)
        print(f"  → {len(text)} chars, {len(chunks)} chunks")

        # Insérer par batch de 50
        for i in range(0, len(chunks), 50):
            batch = chunks[i:i+50]
            collection.add(
                ids        = [c["id"]    for c in batch],
                documents  = [c["text"]  for c in batch],
                metadatas  = [{"source": c["source"], "chunk": c["chunk"]} for c in batch],
            )
        total_chunks += len(chunks)

    print(f"\n✓ Index construit : {total_chunks} chunks dans '{COLLECTION}'")
    print(f"  Stocké dans : {VECTORS_DIR}")
    return total_chunks

if __name__ == "__main__":
    build_index()
