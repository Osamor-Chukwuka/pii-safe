import { creditCardDetector } from "./credit-card.js";
import { emailDetector } from "./email.js";
import { nigeriaDetector } from "./nigeria.js";
import { phoneDetector } from "./phone.js";
import { secretsDetector } from "./secrets.js";

export const builtInDetectors = [
  emailDetector,
  phoneDetector,
  creditCardDetector,
  secretsDetector,
  nigeriaDetector
];

export {
  creditCardDetector,
  emailDetector,
  nigeriaDetector,
  phoneDetector,
  secretsDetector
};
