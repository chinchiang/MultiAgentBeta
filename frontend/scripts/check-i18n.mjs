/** Every Chinese string the console shows must be the Chinese half of t('中文','English') or of a labels() pair. */
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FILES = ['src/App.tsx', 'src/extensions.tsx', 'src/api.ts', 'src/i18n.ts', 'src/main.tsx', 'src/types.ts'];
const CJK = /[一-鿿]/;
// Chinese punctuation (for example the full-width parenthesis in t('）',')')) also marks the Chinese half.
const CHINESE = /[一-鿿　-〿＀-￯]/;
// '中文' labels the language switch in its own language; '本地操作員提供' is a provenance value stored in run data.
const ALLOWED = new Set(['中文', '本地操作員提供']);
const problems = [];
for (const file of FILES) {
  const source = await readFile(resolve(root, file), 'utf8');
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const where = node => `${file}:${sf.getLineAndCharacterOfPosition(node.getStart()).line + 1}`;
  const isT = node => ts.isCallExpression(node) && node.expression.getText() === 't';
  const insideChineseHalf = node => {
    for (let child = node; child.parent; child = child.parent) {
      if (isT(child.parent) && child.parent.arguments[0] === child) return true;
    }
    return false;
  };
  const visit = node => {
    const text = ts.isJsxText(node) ? node.getText()
      : ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text
      : ts.isTemplateExpression(node) ? node.getText() : null;
    if (text !== null && CJK.test(text) && !ALLOWED.has(text.trim())) {
      const parent = node.parent;
      const labelPair = ts.isArrayLiteralExpression(parent) && parent.elements.length === 2 && parent.elements[0] === node && !CJK.test(parent.elements[1].getText());
      if (!insideChineseHalf(node) && !labelPair) problems.push(`${where(node)}: not wrapped in t(): ${text.trim().slice(0, 60)}`);
    }
    if (isT(node)) {
      if (node.arguments.length !== 2) problems.push(`${where(node)}: t() takes the Chinese text and the English text`);
      else if (CJK.test(node.arguments[1].getText())) problems.push(`${where(node)}: the English half contains Chinese`);
      // Calls with variables (backend text that arrives in both languages, label tables) are checked where the text is written.
      else if (ts.isStringLiteralLike(node.arguments[0]) && !CHINESE.test(node.arguments[0].text)) problems.push(`${where(node)}: the first argument should be the Chinese text`);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}
if (problems.length) {
  console.error(problems.join('\n'));
  process.exitCode = 1;
} else {
  console.log(`check-i18n: every visible Chinese string in ${FILES.length} files has an English counterpart`);
}
