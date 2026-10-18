/**
 * GhostTrace — Interactive Cybernetic Binary Canvas Background
 * High-performance 2D canvas with mouse-displacement field and ambient binary flow.
 */

(function () {
    'use strict';

    const canvas = document.getElementById('binary-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    // Check prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let width = 0;
    let height = 0;
    let animationFrameId = null;

    // Mouse tracking with smooth interpolation
    const mouse = {
        x: -1000,
        y: -1000,
        targetX: -1000,
        targetY: -1000,
        radius: 140,
        active: false,
    };

    // Grid configuration
    const fontSize = 14;
    let columns = 0;
    let rows = 0;
    let drops = [];

    class BinaryStream {
        constructor(x, colIndex) {
            this.x = x;
            this.colIndex = colIndex;
            this.reset();
            // Stagger initial positions
            this.y = Math.random() * -height;
        }

        reset() {
            this.y = -20;
            this.speed = (0.7 + Math.random() * 1.3) * (prefersReducedMotion ? 0.3 : 1.0);
            this.length = Math.floor(12 + Math.random() * 18);
            this.chars = [];
            for (let i = 0; i < this.length; i++) {
                this.chars.push(Math.random() > 0.5 ? '1' : '0');
            }
            this.baseOpacity = 0.08 + Math.random() * 0.16;
            this.depth = 0.8 + Math.random() * 0.4; // subtle parallax depth
        }

        update() {
            this.y += this.speed * this.depth;
            // Mutate bits occasionally
            if (Math.random() < 0.02) {
                const idx = Math.floor(Math.random() * this.length);
                this.chars[idx] = this.chars[idx] === '1' ? '0' : '1';
            }

            if (this.y - (this.length * fontSize) > height) {
                this.reset();
            }
        }

        draw() {
            for (let i = 0; i < this.length; i++) {
                const charY = this.y - (i * fontSize);
                if (charY < -fontSize || charY > height + fontSize) continue;

                // Mouse interaction displacement and brighten
                let drawX = this.x;
                let drawY = charY;
                let charOpacity = this.baseOpacity * (1 - (i / this.length) * 0.7);
                let charColor = '0, 184, 107'; // muted green

                if (mouse.active) {
                    const dx = drawX - mouse.x;
                    const dy = drawY - mouse.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < mouse.radius) {
                        const force = (1 - dist / mouse.radius);
                        // Displacement ripple
                        const angle = Math.atan2(dy, dx);
                        const pushDist = force * 24;
                        drawX += Math.cos(angle) * pushDist;
                        drawY += Math.sin(angle) * pushDist;

                        // Brighten nearby characters
                        charOpacity = Math.min(0.85, charOpacity + force * 0.75);
                        charColor = '0, 255, 136'; // bright terminal green
                    }
                }

                // Head character is slightly brighter
                if (i === 0) {
                    charOpacity = Math.min(0.9, charOpacity + 0.3);
                    charColor = '166, 227, 192'; // crisp green-white head
                }

                ctx.font = `${Math.floor(fontSize * this.depth)}px "JetBrains Mono", monospace`;
                ctx.fillStyle = `rgba(${charColor}, ${charOpacity})`;
                ctx.fillText(this.chars[i], drawX, drawY);
            }
        }
    }

    function initGrid() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;

        columns = Math.floor(width / (fontSize * 1.5));
        drops = [];

        for (let i = 0; i < columns; i++) {
            drops.push(new BinaryStream(i * (fontSize * 1.5), i));
        }
    }

    // Debounced resize
    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(initGrid, 150);
    });

    // Mouse movement
    window.addEventListener('mousemove', (e) => {
        mouse.targetX = e.clientX;
        mouse.targetY = e.clientY;
        mouse.active = true;
    }, { passive: true });

    window.addEventListener('mouseleave', () => {
        mouse.active = false;
        mouse.targetX = -1000;
        mouse.targetY = -1000;
    });

    // Animation Loop
    function render() {
        // Smooth mouse interpolation
        if (mouse.active) {
            mouse.x += (mouse.targetX - mouse.x) * 0.12;
            mouse.y += (mouse.targetY - mouse.y) * 0.12;
        } else {
            mouse.x = -1000;
            mouse.y = -1000;
        }

        // Clear canvas with subtle trail
        ctx.fillStyle = 'rgba(5, 8, 7, 0.28)';
        ctx.fillRect(0, 0, width, height);

        // Update and draw drops
        for (let i = 0; i < drops.length; i++) {
            drops[i].update();
            drops[i].draw();
        }

        animationFrameId = requestAnimationFrame(render);
    }

    // Start
    initGrid();
    render();

    // Clean up
    window.addEventListener('beforeunload', () => {
        if (animationFrameId) cancelAnimationFrame(animationFrameId);
    });
})();
