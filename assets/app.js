// Local UI state. htmx owns requests and server-rendered HTML; Alpine owns
// filters, toggles, and clocks. Keep timers tied to their component lifecycle.
document.addEventListener('htmx:config:request', (event) => {
    const token = document.querySelector('meta[name="csrf-token"]')?.content;
    if (token) event.detail.ctx.request.headers['X-CSRF-Token'] = token;
});

document.addEventListener('alpine:init', () => {
    Alpine.data('systemClock', (initialUptime) => ({
        uptime: initialUptime,
        timer: null,
        init() {
            const started = Date.now() - initialUptime * 1000;
            this.timer = setInterval(() => {
                this.uptime = Math.floor((Date.now() - started) / 1000);
            }, 1000);
        },
        destroy() {
            clearInterval(this.timer);
        },
        get formatted() {
            const seconds = this.uptime;
            return `${Math.floor(seconds / 86400)}d ${Math.floor(seconds % 86400 / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`;
        },
        get queryRate() {
            const queries = Number(document.getElementById('live-queries')?.dataset.count || 0);
            return this.uptime > 0 ? (queries / this.uptime).toFixed(1) : '0.0';
        },
    }));

    Alpine.data('pauseTimer', (remaining) => ({
        left: remaining,
        timer: null,
        init() {
            const deadline = Date.now() + remaining * 1000;
            this.timer = setInterval(() => {
                this.left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
                if (this.left === 0) {
                    clearInterval(this.timer);
                    window.location.reload();
                }
            }, 1000);
        },
        destroy() {
            clearInterval(this.timer);
        },
        get formatted() {
            const seconds = String(this.left % 60).padStart(2, '0');
            const minutes = Math.floor(this.left % 3600 / 60);
            return this.left >= 3600
                ? `${Math.floor(this.left / 3600)}:${String(minutes).padStart(2, '0')}:${seconds}`
                : `${minutes}:${seconds}`;
        },
    }));
});
