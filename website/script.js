// Consolidated initialization
document.addEventListener('DOMContentLoaded', function() {
    initMobileNavigation();
    initCodeTabSwitching();
    initTerminalAnimation();
    initCopyButtons();
});

// Mobile navigation toggle
function initMobileNavigation() {
    const navToggle = document.getElementById('navToggle');
    const navMenu = document.getElementById('navMenu');

    if (!navToggle || !navMenu) return;

    navToggle.addEventListener('click', function() {
        const isOpen = navMenu.classList.contains('active');
        navMenu.classList.toggle('active');

        // Update ARIA attribute
        navToggle.setAttribute('aria-expanded', !isOpen);

        // Animate hamburger bars
        const bars = navToggle.querySelectorAll('.bar');
        bars.forEach((bar, index) => {
            if (!isOpen) {
                if (index === 0) {
                    bar.style.transform = 'rotate(-45deg) translate(-5px, 6px)';
                } else if (index === 1) {
                    bar.style.opacity = '0';
                } else {
                    bar.style.transform = 'rotate(45deg) translate(-5px, -6px)';
                }
            } else {
                bar.style.transform = 'none';
                bar.style.opacity = '1';
            }
        });
    });

    // Close mobile menu when clicking on links
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            navMenu.classList.remove('active');
            navToggle.setAttribute('aria-expanded', 'false');
            const bars = navToggle.querySelectorAll('.bar');
            bars.forEach(bar => {
                bar.style.transform = 'none';
                bar.style.opacity = '1';
            });
        });
    });
}

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            const headerOffset = 80;
            const elementPosition = target.getBoundingClientRect().top;
            const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

            window.scrollTo({
                top: offsetPosition,
                behavior: 'smooth'
            });
        }
    });
});

// Code tab switching
function initCodeTabSwitching() {
    const codeTabs = document.querySelectorAll('.code-tab');
    const codeBlocks = document.querySelectorAll('.code-block');

    if (!codeTabs.length) return;

    codeTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const targetTab = this.getAttribute('data-tab');

            // Remove active class from all tabs and blocks
            codeTabs.forEach(t => t.classList.remove('active'));
            codeBlocks.forEach(block => block.classList.remove('active'));

            // Add active class to clicked tab and corresponding block
            this.classList.add('active');
            const targetBlock = document.getElementById(targetTab);
            if (targetBlock) {
                targetBlock.classList.add('active');
            }
        });
    });
}

// Navbar scroll effect
window.addEventListener('scroll', function() {
    const navbar = document.querySelector('.navbar');
    const scrollPosition = window.scrollY;

    if (scrollPosition > 50) {
        navbar.style.backgroundColor = 'rgba(255, 255, 255, 0.98)';
        navbar.style.boxShadow = '0 4px 6px -1px rgb(0 0 0 / 0.1)';
    } else {
        navbar.style.backgroundColor = 'rgba(255, 255, 255, 0.95)';
        navbar.style.boxShadow = 'none';
    }
});

// Terminal typing animation
function initTerminalAnimation() {
    const terminalBody = document.querySelector('.terminal-body');
    if (!terminalBody) return;

    const cursor = terminalBody.querySelector('.terminal-cursor');
    const commands = [
        '$ docker compose up',
        'Pulling ghcr.io/mcpcap/mcpcap:latest',
        "Starting MCP server 'mcpcap' with transport 'http'",
        'Listening on http://127.0.0.1:8080/mcp'
    ];

    let currentCommand = 0;
    let currentChar = 0;

    function createTerminalLine(isOutput = false) {
        const line = document.createElement('div');
        line.className = isOutput ? 'terminal-line output' : 'terminal-line';
        if (!isOutput) {
            line.innerHTML = '<span class="prompt">$</span> ';
        }
        terminalBody.insertBefore(line, cursor);
        return line;
    }

    function typeCommand() {
        if (currentCommand >= commands.length) return;

        const command = commands[currentCommand];
        const isOutput = !command.startsWith('$');
        const currentLine = terminalBody.children[terminalBody.children.length - 2]; // Get last line before cursor

        if (!currentLine || currentChar === 0) {
            // Create new line for this command
            const newLine = createTerminalLine(isOutput);
            if (isOutput) {
                newLine.textContent = '';
            }
        }

        const activeLine = terminalBody.children[terminalBody.children.length - 2];

        if (currentChar < command.length) {
            if (isOutput) {
                activeLine.textContent = command.substring(0, currentChar + 1);
            } else {
                activeLine.innerHTML = '<span class="prompt">$</span> ' + command.substring(2, currentChar + 1);
            }
            currentChar++;
            setTimeout(typeCommand, 50);
        } else {
            // Command finished, move to next
            currentCommand++;
            currentChar = 0;
            setTimeout(typeCommand, 800);
        }
    }

    // Start typing animation after a short delay
    setTimeout(typeCommand, 1000);
}

// Intersection Observer for animations
document.addEventListener('DOMContentLoaded', function() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animationPlayState = 'running';
                entry.target.classList.add('animate-in');
            }
        });
    }, observerOptions);

    // Observe feature cards
    document.querySelectorAll('.feature-card, .module-card, .step').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'all 0.6s ease';
        observer.observe(el);
    });
});

// Add animation styles when elements come into view
const style = document.createElement('style');
style.textContent = `
    .animate-in {
        opacity: 1 !important;
        transform: translateY(0) !important;
    }

    .feature-card.animate-in {
        transition-delay: calc(var(--delay, 0) * 0.1s);
    }
`;
document.head.appendChild(style);

// Set animation delays for feature cards
document.querySelectorAll('.feature-card').forEach((card, index) => {
    card.style.setProperty('--delay', index);
});

// Copy to clipboard functionality for code blocks
function initCopyButtons() {
    // Add copy buttons to code blocks
    const codeBlocks = document.querySelectorAll('.code-block');

    codeBlocks.forEach(block => {
        const copyButton = document.createElement('button');
        copyButton.className = 'copy-button';
        copyButton.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>Copy`;

        copyButton.addEventListener('click', function() {
            const code = block.querySelector('code').textContent;
            navigator.clipboard.writeText(code).then(() => {
                copyButton.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Copied!`;
                copyButton.classList.add('copied');

                setTimeout(() => {
                    copyButton.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>Copy`;
                    copyButton.classList.remove('copied');
                }, 2000);
            });
        });

        block.style.position = 'relative';
        block.appendChild(copyButton);
    });
}

// Add copy button styles
const copyButtonStyles = document.createElement('style');
copyButtonStyles.textContent = `
    .copy-button {
        position: absolute;
        top: 1rem;
        right: 1rem;
        background-color: #334155;
        color: #94a3b8;
        border: 1px solid #475569;
        border-radius: 6px;
        padding: 0.5rem;
        font-size: 0.75rem;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 0.25rem;
        transition: all 0.3s ease;
        opacity: 0.7;
    }

    .copy-button:hover {
        background-color: #475569;
        color: #e2e8f0;
        opacity: 1;
    }

    .copy-button.copied {
        background-color: #059669;
        color: white;
        border-color: #059669;
    }
`;
document.head.appendChild(copyButtonStyles);

// Parallax effect for hero section
window.addEventListener('scroll', function() {
    const scrolled = window.pageYOffset;
    const hero = document.querySelector('.hero');
    if (hero) {
        const rate = scrolled * -0.5;
        hero.style.transform = `translateY(${rate}px)`;
    }
});

// Add loading animation
document.addEventListener('DOMContentLoaded', function() {
    // Remove any loading states and show content
    document.body.classList.add('loaded');

    // Stagger animation for hero stats
    const stats = document.querySelectorAll('.stat');
    stats.forEach((stat, index) => {
        stat.style.opacity = '0';
        stat.style.transform = 'translateY(20px)';
        stat.style.transition = `all 0.6s ease ${index * 0.1}s`;

        setTimeout(() => {
            stat.style.opacity = '1';
            stat.style.transform = 'translateY(0)';
        }, 500 + (index * 100));
    });
});

// Easter egg: Konami code
let konamiCode = [38, 38, 40, 40, 37, 39, 37, 39, 66, 65];
let konamiIndex = 0;

document.addEventListener('keydown', function(e) {
    if (e.keyCode === konamiCode[konamiIndex]) {
        konamiIndex++;
        if (konamiIndex === konamiCode.length) {
            // Add some fun animation
            document.body.style.animation = 'rainbow 2s infinite';
            setTimeout(() => {
                document.body.style.animation = '';
            }, 5000);
            konamiIndex = 0;
        }
    } else {
        konamiIndex = 0;
    }
});

// Add rainbow animation
const rainbowStyles = document.createElement('style');
rainbowStyles.textContent = `
    @keyframes rainbow {
        0% { filter: hue-rotate(0deg); }
        100% { filter: hue-rotate(360deg); }
    }
`;
document.head.appendChild(rainbowStyles);
