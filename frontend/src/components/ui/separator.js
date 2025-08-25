"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Separator = Separator;
var jsx_runtime_1 = require("react/jsx-runtime");
function Separator(_a) {
    var _b = _a.className, className = _b === void 0 ? "" : _b;
    return (0, jsx_runtime_1.jsx)("div", { className: "h-px w-full bg-gray-200 ".concat(className) });
}
