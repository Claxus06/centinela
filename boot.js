/* Centinela — arranque temprano (se carga en <head> antes que la interfaz).
   Anti-clickjacking: si la página se carga dentro de un iframe ajeno, romper el marco. frame-ancestors solo
   funciona por cabecera HTTP; esto lo cubre en GitHub Pages, que no permite configurar cabeceras. */
(function(){try{if(window.top!==window.self){window.top.location=window.self.location.href;}}catch(e){document.documentElement.style.display='none';}})();

/* Estilos puntuales por elemento. La CSP prohíbe los atributos style="" (style-src 'self'), así que el marcado usa
   data-s="…" y aquí se aplican por CSSOM, que la CSP sí permite. El observador se registra antes de que se analice
   <body>, de modo que los elementos estáticos y los que la app inserta después reciben su estilo antes de pintarse.
   Solo se aplica la primera vez (o si data-s cambia), para no pisar los cambios que la app hace luego por JS. */
(function () {
  var done = new WeakMap();
  function apply(el) { var s = el.getAttribute('data-s'); if (s !== null && done.get(el) !== s) { el.style.cssText = s; done.set(el, s); } }
  function scan(n) { if (n.nodeType !== 1) return; if (n.hasAttribute('data-s')) apply(n); var l = n.querySelectorAll('[data-s]'); for (var i = 0; i < l.length; i++) apply(l[i]); }
  new MutationObserver(function (ms) {
    for (var i = 0; i < ms.length; i++) { var m = ms[i]; if (m.type === 'attributes') apply(m.target); else for (var j = 0; j < m.addedNodes.length; j++) scan(m.addedNodes[j]); }
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['data-s'] });
})();
