#!/usr/bin/env python3
"""
rag_query.py — Moteur RAG : cherche dans la base vectorielle + génère avec llama3.
Importé par app.py pour les routes /api/rag/*.
"""
import os, requests, sys

VECTORS_DIR = os.path.join(os.path.dirname(__file__), "vectors")
COLLECTION  = "soc_knowledge"
OLLAMA_URL  = os.getenv("OLLAMA_URL", "http://localhost:11434")
N_RESULTS   = 4   # chunks à récupérer


def _get_collection():
    import chromadb
    from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
    client   = chromadb.PersistentClient(path=VECTORS_DIR)
    embed_fn = OllamaEmbeddingFunction(
        model_name="nomic-embed-text",
        url=f"{OLLAMA_URL}/api/embeddings"
    )
    return client.get_collection(COLLECTION, embedding_function=embed_fn)


def search(query: str, n: int = N_RESULTS) -> list[dict]:
    """Recherche sémantique dans la base vectorielle."""
    col = _get_collection()
    res = col.query(query_texts=[query], n_results=n)
    results = []
    for doc, meta, dist in zip(
        res["documents"][0],
        res["metadatas"][0],
        res["distances"][0]
    ):
        results.append({
            "text":     doc,
            "source":   meta.get("source", ""),
            "score":    round(1 - dist, 3),  # cosine similarity
        })
    return results


def rag_answer(question: str, model: str = "llama3", timeout: int = 120) -> dict:
    """
    RAG complet :
      1. Cherche les chunks pertinents
      2. Construit un prompt avec le contexte
      3. Génère la réponse avec llama3
    """
    # Récupérer le contexte
    chunks = search(question, n=N_RESULTS)
    if not chunks:
        return {"answer": "Aucune information trouvée dans la base de connaissances.", "sources": []}

    context = "\n\n---\n\n".join(
        f"[Source: {c['source']}]\n{c['text']}" for c in chunks
    )

    prompt = (
        "Tu es un expert SOC (Security Operations Center). "
        "Réponds à la question en te basant UNIQUEMENT sur les extraits de documentation ci-dessous. "
        "Si la réponse n'est pas dans les extraits, dis-le clairement. "
        "Réponds en français, de façon structurée et concise.\n\n"
        f"=== DOCUMENTATION SOC ===\n{context}\n\n"
        f"=== QUESTION ===\n{question}\n\n"
        "=== RÉPONSE ==="
    )

    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=timeout
        )
        r.raise_for_status()
        answer = r.json().get("response", "").strip()
    except requests.exceptions.Timeout:
        answer = "Timeout Ollama — réessayez."
    except Exception as e:
        answer = f"Erreur Ollama : {e}"

    sources = list({c["source"] for c in chunks})
    return {
        "answer":  answer,
        "sources": sources,
        "chunks":  [{"source": c["source"], "score": c["score"], "text": c["text"][:200]} for c in chunks],
    }


if __name__ == "__main__":
    q = " ".join(sys.argv[1:]) or "Quelles sont les étapes d'un playbook SSH brute force ?"
    print(f"\nQuestion : {q}\n")
    res = rag_answer(q)
    print(f"Sources : {res['sources']}\n")
    print(res["answer"])
