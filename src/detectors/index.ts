import { creditCardDetector } from "./credit-card.js";
import { emailDetector } from "./email.js";
import { financeDetector } from "./finance.js";
import { healthDetector } from "./health.js";
import { ipDetector } from "./ip.js";
import { nigeriaDetector } from "./nigeria.js";
import { phoneDetector } from "./phone.js";
import { secretsDetector } from "./secrets.js";

export const builtInDetectors = [
  emailDetector,
  phoneDetector,
  creditCardDetector,
  ipDetector,
  financeDetector,
  healthDetector,
  secretsDetector,
  nigeriaDetector
];

export {
  creditCardDetector,
  emailDetector,
  financeDetector,
  healthDetector,
  ipDetector,
  nigeriaDetector,
  phoneDetector,
  secretsDetector
};
