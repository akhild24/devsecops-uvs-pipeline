from scripts.post_samples import VULNERABLE_PAYLOAD, seed_sample


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self.body = body or {}

    def json(self):
        return self.body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeClient:
    def __init__(self, existing_score, whatif_response):
        self.existing_score = existing_score
        self.whatif_response = whatif_response
        self.posts = []

    def get(self, url):
        if "/v1/score/" in url:
            return self.existing_score
        return self.whatif_response

    def post(self, url, json):
        self.posts.append((url, json))
        return FakeResponse(
            200, {"final_score": 30.0, "risk_level": "Medium"}
        )


def test_demo_sample_is_submitted_to_the_api():
    client = FakeClient(
        FakeResponse(200, {"risk_level": "High"}),
        FakeResponse(404),
    )

    seed_sample(client, "http://localhost:8000", VULNERABLE_PAYLOAD)

    assert len(client.posts) == 1
    assert client.posts[0][1]["trivy_raw"]["Results"][0]["Vulnerabilities"][0]["PkgName"] == "openssl"


def test_demo_sample_is_idempotently_upserted_even_when_already_present():
    client = FakeClient(
        FakeResponse(200, {"risk_level": "Low"}),
        FakeResponse(200, []),
    )

    seed_sample(client, "http://localhost:8000", VULNERABLE_PAYLOAD)

    assert len(client.posts) == 1
