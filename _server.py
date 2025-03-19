from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from scanner import scanner_run, scanner_validate_input

import concurrent.futures
from httpx import AsyncClient

app = FastAPI()


class ProxyRequest(BaseModel):
    header: str = Field(alias="Header")
    header_value: str = Field(alias="Header-value")
    target: str = Field(alias="Target")
    method: str = Field(alias="Method")


class ProxyScanner(BaseModel):
    target: str
    count: str


@app.get("/scan")
def scan(proxyScanner: ProxyScanner, response_class=PlainTextResponse):
    try:
        ipList = scanner_validate_input(proxyScanner.target, proxyScanner.count)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(scanner_run, ipList)
            results = "\n".join(results)
        return f"{'-' * 100}\n{results}{'-' * 100}\n"
    except Exception as err:
        err_text = f"Scan parameters are not correct!\nProvided parameters: {proxyScanner.target=}, {proxyScanner.count=}\n[error: {err}]"
        print(err_text)
        return err_text


@app.post("/send-request")
async def send_request(proxyRequest: ProxyRequest):
    headers = {proxyRequest.header: proxyRequest.header_value}
    async with AsyncClient(base_url=proxyRequest.target, headers=headers) as client:
        try:
            if proxyRequest.method == "GET":
                res = await client.get("")
            if proxyRequest.method == "POST":
                res = await client.post("")
        except Exception as err:
            return f"Bad response! [error: {err}]"
        return res.text
