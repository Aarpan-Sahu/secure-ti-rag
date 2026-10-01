"""HTTP mock of MISP (/events/restSearch) and OpenCTI (/graphql) backed by the synthetic fixtures.

    uvicorn tools.mock_feeds_server:app --port 9000
    TIRAG_MISP_URL=http://localhost:9000 TIRAG_MISP_API_KEY=mock-misp-key \
    TIRAG_OPENCTI_URL=http://localhost:9000 TIRAG_OPENCTI_TOKEN=mock-opencti-token \
    tirag ingest --source all --full

For connector development only. Credentials are the fixed mock values above.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tirag.connectors.mock_feeds import MockFeeds

app = FastAPI(title="Mock MISP + OpenCTI", docs_url=None, redoc_url=None)
feeds = MockFeeds()


@app.post("/events/restSearch")
async def misp_search(request: Request) -> JSONResponse:
    status, payload = feeds.misp_search(request.headers, await request.json())  # type: ignore[arg-type]
    return JSONResponse(payload, status_code=status)


@app.post("/graphql")
async def graphql(request: Request) -> JSONResponse:
    status, payload = feeds.opencti_graphql(request.headers, await request.json())  # type: ignore[arg-type]
    return JSONResponse(payload, status_code=status)
