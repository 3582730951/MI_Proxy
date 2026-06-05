import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  scenarios: {
    subscription_smoke: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.SUBSCRIPTION_RPS || 50),
      timeUnit: "1s",
      duration: __ENV.DURATION || "1m",
      preAllocatedVUs: 50,
      maxVUs: 500,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.001"],
    http_req_duration: ["p(99)<800"],
  },
};

export default function () {
  const token = __ENV.SUBSCRIPTION_TOKEN || "invalid-token";
  const base = __ENV.BASE_URL || "http://127.0.0.1:8080";
  const res = http.get(`${base}/sub/${token}/sing-box`);
  check(res, {
    "not 5xx": (r) => r.status < 500,
    "rejected or served": (r) => [200, 304, 404, 410, 429].includes(r.status),
  });
  sleep(0.1);
}

