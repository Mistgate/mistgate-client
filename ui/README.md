# The window

Tauri 2 + React. The screens are the files of the design canvas, rendered as they are:

- `../design/project/*.dc.html` are the masters of the design (Main, Routes, Diag, Settings, Tray, Setup, …), with
  `app.css` and the tokens. `../design/blobs/` are its images.
- `pnpm design` (`tools/dc-import.mjs`) splits each master into `src/screens/<Name>.html` (the template),
  `<Name>.logic.js` (its state class) and `<Name>.props.json`. Run it again when the design changes; do not edit the
  generated files.
- `src/dc.tsx` renders a template: `{{holes}}`, `<sc-if>`, `<sc-for>`, `<dc-import>`, and links between screens
  (`<a href="Routes.dc.html">`).

Today every screen runs on the mock state of the design. The Go service replaces that state screen by screen; what is
not wired yet stays disabled or hidden.

```sh
pnpm install
pnpm dev            # the browser: http://localhost:5183/?screen=Diag&theme=light (the desk with the state switchers)
pnpm tauri dev      # the app window, 1000×660, frameless
pnpm build && pnpm tauri build --no-bundle
```

`?shell` in the browser shows a screen the way the app window does, without the desk.
