module.exports = {
  extends: ['@commitlint/config-conventional'],
  ignores: [
    // Skip bot-generated commits (e.g. greptile-apps[bot], dependabot)
    (msg) => /^\s*Update\s+\.github\//i.test(msg),
  ],
};
