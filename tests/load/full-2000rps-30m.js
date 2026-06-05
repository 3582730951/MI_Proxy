import http from "k6/http";
import { check } from "k6";

export const options = {
  scenarios: {
    peak_subscription: {
      executor: "constant-arrival-rate",
      rate: 2000,
      timeUnit: "1s",
      duration: "30m",
      preAllocatedVUs: 1000,
      maxVUs: 10000,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.001"],
    http_req_duration: ["p(99)<800"],
  },
};

export default function () {
  const token = __ENV.SUBSCRIPTION_TOKEN;
  const base = __ENV.BASE_URL || "http://127.0.0.1:8080";
  const res = http.get(`${base}/sub/${token}/sing-box`);
  check(res, {
    "subscription status ok": (r) => r.status === 200 || r.status === 304,
  });
}

