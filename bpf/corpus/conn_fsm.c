/*
 * A TCP-like connection state machine with RTT estimation (RFC 6298) and Reno congestion control, as a flow
 * tracker in a network plugin keeps it: each event updates a dozen fields of a connection that the handler works on
 * as locals and writes back at the end.
 */
#include "corpus.h"

enum { CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT, TIME_WAIT };
enum { EV_SYN_ACK, EV_ACK, EV_DUP_ACK, EV_TIMEOUT, EV_SEND, EV_FIN, EV_RESET };

struct conn {
    u32 state;
    u32 snd_una, snd_nxt, rcv_nxt;
    u32 cwnd, ssthresh, wnd;
    s32 srtt, rttvar, rto;
    u32 dup_acks, retrans, sent, acked;
    u64 bytes;
};

#define CONNS 16
static struct conn conns[CONNS];

static void step(struct conn *c, u32 ev, u32 arg, u32 now) {
    u32 state = c->state, una = c->snd_una, nxt = c->snd_nxt, rcv = c->rcv_nxt;
    u32 cwnd = c->cwnd, ssthresh = c->ssthresh, wnd = c->wnd;
    s32 srtt = c->srtt, rttvar = c->rttvar, rto = c->rto;
    u32 dups = c->dup_acks, retrans = c->retrans, sent = c->sent, acked = c->acked;
    u64 bytes = c->bytes;

    switch (state) {
    case CLOSED:
        if (ev == EV_SEND) {
            state = SYN_SENT;
            una = nxt = arg;
            nxt++;
            cwnd = 10;
            ssthresh = 64;
            rto = 1000;
            srtt = rttvar = 0;
        }
        break;
    case SYN_SENT:
        if (ev == EV_SYN_ACK) {
            state = ESTABLISHED;
            rcv = arg + 1;
            una = nxt;
            srtt = (s32)(now & 0xff) << 3;
            rttvar = srtt >> 1;
        } else if (ev == EV_TIMEOUT) {
            rto = rto * 2 > 60000 ? 60000 : rto * 2;
            retrans++;
        } else if (ev == EV_RESET) {
            state = CLOSED;
        }
        break;
    case ESTABLISHED:
        if (ev == EV_SEND) {
            u32 room = una + (cwnd < wnd ? cwnd : wnd) * 1460 - nxt;
            u32 len = arg < room ? arg : room;
            nxt += len;
            sent++;
            bytes += len;
        } else if (ev == EV_ACK) {
            u32 ack = una + (arg % (nxt - una + 1));
            if (ack > una) {
                u32 newly = ack - una;
                una = ack;
                acked += newly;
                dups = 0;
                s32 rtt = (s32)(now % 400) + 20;
                s32 err = rtt - (srtt >> 3);
                srtt += err;
                rttvar += (err < 0 ? -err : err) - (rttvar >> 2);
                rto = (srtt >> 3) + rttvar;
                rto = rto < 200 ? 200 : rto;
                if (cwnd < ssthresh)
                    cwnd += newly / 1460 + 1;
                else
                    cwnd += (1460 * 1460 / (cwnd * 1460)) + 1;
            }
            wnd = (arg >> 8 & 0x3f) + 4;
            rcv += arg & 7;
        } else if (ev == EV_DUP_ACK) {
            if (++dups == 3) {
                ssthresh = cwnd / 2 > 2 ? cwnd / 2 : 2;
                cwnd = ssthresh + 3;
                retrans++;
            } else if (dups > 3) {
                cwnd++;
            }
        } else if (ev == EV_TIMEOUT) {
            ssthresh = cwnd / 2 > 2 ? cwnd / 2 : 2;
            cwnd = 1;
            rto = rto * 2 > 60000 ? 60000 : rto * 2;
            retrans++;
            nxt = una;
        } else if (ev == EV_FIN) {
            state = FIN_WAIT;
            nxt++;
        } else if (ev == EV_RESET) {
            state = CLOSED;
        }
        break;
    case FIN_WAIT:
        if (ev == EV_ACK) {
            state = TIME_WAIT;
            una = nxt;
        } else if (ev == EV_TIMEOUT) {
            retrans++;
        }
        break;
    default:
        if (ev == EV_TIMEOUT || ev == EV_RESET)
            state = CLOSED;
        break;
    }

    c->state = state;
    c->snd_una = una;
    c->snd_nxt = nxt;
    c->rcv_nxt = rcv;
    c->cwnd = cwnd;
    c->ssthresh = ssthresh;
    c->wnd = wnd;
    c->srtt = srtt;
    c->rttvar = rttvar;
    c->rto = rto;
    c->dup_acks = dups;
    c->retrans = retrans;
    c->sent = sent;
    c->acked = acked;
    c->bytes = bytes;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 i = 0; i < CONNS; i++)
        conns[i] = (struct conn){.wnd = 16};
    for (u32 now = 0; now < 3000; now++) {
        u64 r = rng_next(&rng);
        u32 ev = (u32)(r >> 8) % 16;
        ev = ev < 6 ? EV_SEND : ev < 11 ? EV_ACK : ev < 13 ? EV_DUP_ACK : ev < 14 ? EV_TIMEOUT : ev < 15 ? EV_SYN_ACK
           : (r >> 40 & 7) ? EV_FIN : EV_RESET;
        step(&conns[r % CONNS], ev, (u32)(r >> 32), now);
    }
    for (u32 i = 0; i < CONNS; i++) {
        struct conn *c = &conns[i];
        acc = (acc << 9 | acc >> 55) ^ c->bytes ^ (u64)c->cwnd << 32 ^ c->retrans ^ (u64)c->rto << 16 ^ c->state;
    }
    return acc;
}
