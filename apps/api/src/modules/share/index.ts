import { config } from "../../config.js";
import * as secure from "./secure/share.controller.js";
import * as vulnerable from "./vulnerable/share.controller.js";
export const shareController = config.secureMode ? secure : vulnerable;
