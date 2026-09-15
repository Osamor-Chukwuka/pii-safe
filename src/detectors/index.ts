import { creditCardDetector } from "./credit-card.js";
import { emailDetector } from "./email.js";
import { ipDetector } from "./ip.js";
import { nigeriaDetector } from "./nigeria.js";
import { phoneDetector } from "./phone.js";
import { secretsDetector } from "./secrets.js";

export const builtInDetectors = [
  emailDetector,
  phoneDetector,
  creditCardDetector,
  ipDetector,
  secretsDetector,
  nigeriaDetector
];

export {
  creditCardDetector,
  emailDetector,
  ipDetector,
  nigeriaDetector,
  phoneDetector,
  secretsDetector
};
