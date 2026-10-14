/* Threat Check 3D scene: wireframe globe, orbit rings, telemetry particles.
   Needs Three.js (global THREE) and a <canvas id="scene">. Safe to load without either:
   the page falls back to the CSS background. Reacts to:
   - mouse / touch (parallax tilt)
   - scroll (globe drifts and dims)
   - form submit (scan pulse + faster spin)
   - #result[data-level] (globe tint matches the threat level) */
(function () {
  'use strict';

  var canvas = document.getElementById('scene');
  if (!canvas || typeof THREE === 'undefined') return;

  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: true, powerPreference: 'low-power' });
  } catch (e) {
    return; // no WebGL: CSS background remains
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  var LEVEL_COLORS = { idle: 0x00f0ff, low: 0x2dffa0, medium: 0xffc233, high: 0xff6b3d, critical: 0xff2a5f };
  var VIOLET = 0x7000ff;

  var scene = new THREE.Scene();
  var camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
  camera.position.z = 9;

  var rig = new THREE.Group();           // follows pointer + scroll
  scene.add(rig);
  var globe = new THREE.Group();         // spins
  rig.add(globe);

  var mainColor = new THREE.Color(LEVEL_COLORS.idle);
  var targetColor = new THREE.Color(LEVEL_COLORS.idle);

  // wireframe shell (lat/long grid) and inner icosahedron
  var gridMat = new THREE.MeshBasicMaterial({ color: mainColor, wireframe: true, transparent: true, opacity: 0.22 });
  globe.add(new THREE.Mesh(new THREE.SphereGeometry(2.4, 32, 20), gridMat));

  var coreMat = new THREE.MeshBasicMaterial({ color: VIOLET, wireframe: true, transparent: true, opacity: 0.35 });
  var core = new THREE.Mesh(new THREE.IcosahedronGeometry(1.7, 2), coreMat);
  globe.add(core);

  // surface nodes
  var nodeCount = 160, nodePos = new Float32Array(nodeCount * 3);
  for (var i = 0; i < nodeCount; i++) {
    var u = Math.random() * 2 - 1, t = Math.random() * Math.PI * 2, s = Math.sqrt(1 - u * u);
    nodePos[i * 3] = 2.42 * s * Math.cos(t);
    nodePos[i * 3 + 1] = 2.42 * u;
    nodePos[i * 3 + 2] = 2.42 * s * Math.sin(t);
  }
  var nodeGeo = new THREE.BufferGeometry();
  nodeGeo.setAttribute('position', new THREE.BufferAttribute(nodePos, 3));
  var nodeMat = new THREE.PointsMaterial({ color: mainColor, size: 0.07, transparent: true, opacity: 0.95, depthWrite: false, blending: THREE.AdditiveBlending });
  globe.add(new THREE.Points(nodeGeo, nodeMat));

  // orbit rings
  function ring(radius, tiltX, tiltZ, color, opacity) {
    var m = new THREE.Mesh(new THREE.TorusGeometry(radius, 0.006, 8, 160),
      new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: opacity, blending: THREE.AdditiveBlending }));
    m.rotation.x = tiltX; m.rotation.z = tiltZ;
    rig.add(m);
    return m;
  }
  var ring1 = ring(3.1, 1.25, 0.2, mainColor, 0.55);
  var ring2 = ring(3.6, 1.9, -0.5, VIOLET, 0.5);

  // scan pulse ring (expands on submit)
  var pulseMat = new THREE.MeshBasicMaterial({ color: mainColor, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, side: THREE.DoubleSide });
  var pulse = new THREE.Mesh(new THREE.RingGeometry(2.45, 2.5, 96), pulseMat);
  rig.add(pulse);
  var pulseT = -1;

  // floating telemetry particles
  var pCount = 700, pPos = new Float32Array(pCount * 3), pVel = new Float32Array(pCount);
  for (var j = 0; j < pCount; j++) {
    pPos[j * 3] = (Math.random() - 0.5) * 26;
    pPos[j * 3 + 1] = (Math.random() - 0.5) * 16;
    pPos[j * 3 + 2] = (Math.random() - 0.5) * 14 - 2;
    pVel[j] = 0.15 + Math.random() * 0.45;
  }
  var pGeo = new THREE.BufferGeometry();
  pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
  var pMat = new THREE.PointsMaterial({ color: 0x8fdcff, size: 0.035, transparent: true, opacity: 0.6, depthWrite: false, blending: THREE.AdditiveBlending });
  var particles = new THREE.Points(pGeo, pMat);
  scene.add(particles);

  /* ---------- layout ---------- */
  var width = 0, height = 0;
  function resize() {
    width = window.innerWidth; height = window.innerHeight;
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    var wide = width > 900;
    rig.position.set(wide ? 3.6 : 0, wide ? 0.2 : 2.2, 0);
    rig.scale.setScalar(wide ? 1 : 0.7);
  }
  window.addEventListener('resize', resize);
  resize();

  /* ---------- input ---------- */
  var mx = 0, my = 0, tx = 0, ty = 0, scrollY = 0, spinBoost = 0;
  window.addEventListener('pointermove', function (e) {
    tx = (e.clientX / width) * 2 - 1;
    ty = (e.clientY / height) * 2 - 1;
  }, { passive: true });
  window.addEventListener('scroll', function () { scrollY = window.scrollY || 0; }, { passive: true });

  var form = document.getElementById('form');
  if (form) form.addEventListener('submit', function () { pulseT = 0; spinBoost = 1; });

  var resultBox = document.getElementById('result');
  function applyLevel() {
    var lvl = resultBox && !resultBox.hidden ? resultBox.getAttribute('data-level') : null;
    targetColor.setHex(LEVEL_COLORS[lvl] || LEVEL_COLORS.idle);
    if (lvl) { pulseT = 0; spinBoost = 0.6; }
  }
  if (resultBox && window.MutationObserver) {
    new MutationObserver(applyLevel).observe(resultBox, { attributes: true, attributeFilter: ['data-level', 'hidden'] });
  }

  /* ---------- loop ---------- */
  var clock = new THREE.Clock(), running = true;
  document.addEventListener('visibilitychange', function () {
    running = !document.hidden;
    if (running) { clock.getDelta(); loop(); }
  });

  function frame(dt) {
    mainColor.lerp(targetColor, Math.min(1, dt * 3));
    gridMat.color.copy(mainColor); nodeMat.color.copy(mainColor);
    ring1.material.color.copy(mainColor); pulseMat.color.copy(mainColor);

    spinBoost *= Math.pow(0.35, dt);
    globe.rotation.y += dt * (0.12 + spinBoost * 2.2);
    core.rotation.x -= dt * 0.18; core.rotation.z += dt * 0.1;
    ring1.rotation.y += dt * 0.25; ring2.rotation.y -= dt * 0.18;

    mx += (tx - mx) * Math.min(1, dt * 3);
    my += (ty - my) * Math.min(1, dt * 3);
    rig.rotation.y = mx * 0.35;
    rig.rotation.x = my * 0.22 + scrollY * 0.0004;
    var fade = Math.max(0.25, 1 - scrollY / 900);
    gridMat.opacity = 0.22 * fade; coreMat.opacity = 0.35 * fade; nodeMat.opacity = 0.95 * fade;
    camera.position.x = mx * 0.4; camera.position.y = -my * 0.25; camera.lookAt(0, 0, 0);

    if (pulseT >= 0) {
      pulseT += dt;
      var k = pulseT / 1.4;
      pulse.scale.setScalar(1 + k * 1.2);
      pulseMat.opacity = Math.max(0, 0.8 * (1 - k));
      pulse.lookAt(camera.position);
      if (k >= 1) { pulseT = -1; pulseMat.opacity = 0; }
    }

    var arr = pGeo.attributes.position.array;
    for (var n = 0; n < pCount; n++) {
      arr[n * 3 + 1] += pVel[n] * dt;
      if (arr[n * 3 + 1] > 8) arr[n * 3 + 1] = -8;
    }
    pGeo.attributes.position.needsUpdate = true;
    particles.rotation.y += dt * 0.01;
  }

  function loop() {
    if (!running) return;
    var dt = Math.min(clock.getDelta(), 0.05);
    if (!reduceMotion) frame(dt);
    renderer.render(scene, camera);
    requestAnimationFrame(loop);
  }

  if (reduceMotion) { frame(0); renderer.render(scene, camera); window.addEventListener('resize', function () { renderer.render(scene, camera); }); }
  else loop();
})();
