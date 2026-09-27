/**
 * AuthShield 360 - In-memory event bus + pub/sub for the real-time SOC feed
 * and per-user cross-device push. Any subscriber can filter by topic:
 *   '*'           - every event (global SOC dashboard)
 *   'cross:<uid>' - cross-device approval requests for a specific user
 *   'audit', 'alert', 'sim' - category filters
 */
const listeners = new Set();

/**
 * @param {function(string):void} onEvent  receives JSON string
 * @param {string|string[]} topics         '*' or categories / 'cross:<uid>'
 * @returns unsubscribe fn
 */
export function subscribeEvents(onEvent, topics = '*') {
    const sub = { fn: onEvent, topics: Array.isArray(topics) ? topics : [topics] };
    listeners.add(sub);
    return () => listeners.delete(sub);
}

export function publish(topic, event) {
    const payload = JSON.stringify(event);
    for (const sub of [...listeners]) {
        if (sub.topics.includes('*') || sub.topics.includes(topic)) {
            try { sub.fn(payload); } catch { listeners.delete(sub); }
        }
    }
}

export function listenerCount() {
    return listeners.size;
}