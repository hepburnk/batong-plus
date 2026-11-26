/* ============================================================
   이어줌 AI — AI 업무 인수인계 웹앱
   빌드·서버 없이 동작하는 순수 HTML/CSS/JS.
   ① 개인정보 마스킹  ② 7단 인수인계서 자동 생성
   ③ 인계 완료도 점수  ④ 후임자 Q&A  ⑤ 내보내기
   ============================================================ */
(function () {
  'use strict';

  /* ---------------- 기본 유틸 ---------------- */
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };
  var TODAY = new Date(); TODAY.setHours(0, 0, 0, 0);
  var DAY = 86400000;
  var uidSeq = 0;
  var uid = function (p) { return (p || 'x') + (++uidSeq); };
  var pad2 = function (n) { return (n < 10 ? '0' : '') + n; };
  var fmtD = function (d) { return d ? d.getFullYear() + '.' + pad2(d.getMonth() + 1) + '.' + pad2(d.getDate()) + '.' : ''; };
  var fmtDateStr = function (s) {
    var m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
    return m ? m[1] + '. ' + (+m[2]) + '. ' + (+m[3]) + '.' : (s || '');
  };
  var dateInput = function (d) { return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); };
  var clamp = function (v, a, b) { return Math.max(a, Math.min(b, v)); };
  var trunc = function (s, n) { return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  var digits = function (s) { return String(s).replace(/\D/g, ''); };
  var stars = function (s) { return String(s).replace(/\d/g, '*'); };

  var toastTimer = null;
  function toast(msg, isErr) {
    var el = $('#toast');
    el.textContent = msg;
    el.className = 'toast show' + (isErr ? ' err' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.className = 'toast' + (isErr ? ' err' : ''); }, 3200);
  }

  /* ---------------- 저장 ---------------- */
  var LS_PREFIX = 'batongplus.v1.';
  function lsGet(k, d) {
    try { var v = localStorage.getItem(LS_PREFIX + k); return v ? JSON.parse(v) : d; } catch (e) { return d; }
  }
  function lsSet(k, v) {
    try { localStorage.setItem(LS_PREFIX + k, JSON.stringify(v)); } catch (e) { /* 저장 불가 환경 무시 */ }
  }

  /* ---------------- 상태 ---------------- */
  var SECTIONS = [
    { key: 'summary', no: '①', label: '핵심 업무 요약', weight: 10, target: 3 },
    { key: 'tasks', no: '②', label: '진행 중·미완료 과제', weight: 20, target: 3 },
    { key: 'routines', no: '③', label: '반복 루틴 캘린더', weight: 15, target: 3 },
    { key: 'contacts', no: '④', label: '이해관계자·비상연락망', weight: 15, target: 2 },
    { key: 'faq', no: '⑤', label: '트러블슈팅 FAQ', weight: 15, target: 2 },
    { key: 'onboarding', no: '⑥', label: '인수자 첫 7일 온보딩', weight: 10, target: 5 },
    { key: 'risks', no: '⑦', label: '리스크·주의사항', weight: 15, target: 2 }
  ];

  var state = {
    sources: [],           // {id, name, kind, raw, masked, findings}
    maskOn: true,
    maskLevel: 'partial',
    meta: { org: '', from: '', to: '', date: '' },
    doc: null,
    aiUsedBy: '',
    checks: [],
    lastGenerated: null
  };

  /* ============================================================
     1. 개인정보 탐지·마스킹
     ============================================================ */
  var PII = [
    {
      type: 'rrn', label: '주민등록번호', risk: 'high',
      re: /(\d{6})\s?[-–—]\s?([1-8])\d{6}/g,
      mask: function (m, g, lv) {
        return lv === 'full' ? stars(m) : g[1] + '-××××××';
      }
    },
    {
      type: 'card', label: '카드번호', risk: 'high',
      re: /\b(\d{4})[- ](\d{4})[- ](\d{4})[- ](\d{4})\b/g,
      mask: function (m, g, lv) { return lv === 'full' ? stars(m) : g[1] + '-××××-××××-' + g[4]; }
    },
    {
      type: 'email', label: '이메일', risk: 'mid',
      re: /([A-Za-z0-9._%+-]{2,})@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g,
      mask: function (m, g, lv) {
        var u = g[1];
        return (lv === 'full' ? '×××' : u.slice(0, 2) + '×××') + '@' + g[2];
      }
    },
    {
      type: 'phone', label: '전화번호', risk: 'mid',
      re: /(0\d{1,2})[-\s.]?(\d{3,4})[-\s.](\d{4})/g,
      mask: function (m, g, lv) { return lv === 'full' ? stars(m) : g[1] + '-××××-' + g[3]; }
    },
    {
      type: 'bizno', label: '사업자등록번호', risk: 'mid',
      re: /\b(\d{3})-(\d{2})-(\d{5})\b/g,
      mask: function (m, g, lv) { return lv === 'full' ? stars(m) : g[1] + '-' + g[2] + '-×××××'; }
    },
    {
      type: 'account', label: '계좌번호', risk: 'high',
      re: /\b(\d{2,6})[- ](\d{2,6})[- ](\d{2,7})(?:[- ](\d{1,4}))?\b/g,
      mask: function (m, g, lv) {
        if (lv === 'full') return stars(m);
        var tail = g[3].slice(-4);
        return g[1] + '-' + stars(g[2]) + '-' + new Array(Math.max(1, g[3].length - 3)).join('×') + tail;
      }
    }
  ];

  // 날짜 모양(2026-11-26)은 계좌번호로 오인하지 않는다
  function looksLikeDate(a, b, c) {
    return (/^(19|20)\d{2}$/.test(a) && +b >= 1 && +b <= 12 && +c >= 1 && +c <= 31);
  }

  function scanPII(text, level) {
    var findings = [];
    var taken = [];   // [start, end]
    var out = text;

    PII.forEach(function (p) {
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        var s = m.index, e = m.index + m[0].length;
        var overlap = taken.some(function (r) { return s < r[1] && e > r[0]; });
        if (overlap) continue;
        if (p.type === 'account' && looksLikeDate(m[1], m[2], m[3])) continue;
        if (p.type === 'account' && (m[0].length < 9)) continue;
        taken.push([s, e]);
        findings.push({
          type: p.type, label: p.label, risk: p.risk,
          raw: m[0], masked: p.mask.apply(null, [m[0], m, level]), index: s
        });
      }
    });

    // 뒤에서부터 치환해 인덱스가 밀리지 않게 한다
    findings.slice().sort(function (a, b) { return b.index - a.index; }).forEach(function (f) {
      out = out.slice(0, f.index) + f.masked + out.slice(f.index + f.raw.length);
    });

    return { masked: out, findings: findings.sort(function (a, b) { return a.index - b.index; }) };
  }

  function allFindings() {
    var map = {};
    state.sources.forEach(function (s) {
      (s.findings || []).forEach(function (f) { map[f.type] = (map[f.type] || 0) + 1; });
    });
    return map;
  }

  function processedText(src) { return state.maskOn ? src.masked : src.raw; }

  /* ============================================================
     2. 문장 분류·파싱
     ============================================================ */
  var RE = {
    routine: /(매일|매주|매월|매달|매분기|매년|매반기|정기|주기|분기별|월초|월말|매\s?\d{1,2}\s?일|매\s?[월화수목금토일]요일|첫째\s?주|둘째\s?주|셋째\s?주|넷째\s?주|마지막\s?주)/,
    risk: /(주의|유의|금지|리스크|위험|벌칙|과태료|처벌|감사|청탁|개인정보|보안|반출|유출|위약|법규|징계|말\s?것|하지\s?말|결재선|손실|사고|내부\s?통제)/,
    faq: /(오류|장애|안\s?됨|안됨|실패|반려|대처|폭언|트러블|FAQ|이의\s?신청|민원\s?접수|문의\s?가|안\s?바뀌)/i,
    task: /(까지|마감|기한|제출|송부|보고|결재|상신|요청|회신|진행|추진|예정|완료|독촉|확인조사|대기|착수|준비|점검|조율|수립)/,
    contact: /(연락|전화|번호|내선|당직|비상|@)/,
    arrow: /(→|->|⇒|▶)/
  };

  function headingType(h) {
    if (!h) return 'info';
    if (/(진행|추진|미완|과제|현안|중점|당면)/.test(h)) return 'task';
    if (/(정기|반복|루틴|주기|일정|캘린더|매일|매주|매월)/.test(h)) return 'routine';
    if (/(연락|이해관계|관계자|비상|네트워크|담당자|조직)/.test(h)) return 'contact';
    if (/(문제|대응|FAQ|트러블|장애|조치|민원\s?응대|질의)/i.test(h)) return 'faq';
    if (/(주의|리스크|유의|금지|보안|개인정보|위험|준수)/.test(h)) return 'risk';
    return 'info';
  }

  function cleanLine(l) {
    return l
      .replace(/^#{1,6}\s*/, '')
      .replace(/^[-*•·▪▫ㅇ○●◦]\s*/, '')
      .replace(/^\d+[.)]\s*/, '')
      .replace(/^\[[ xX]\]\s*/, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function isHeading(l) { return /^#{1,6}\s/.test(l) || /^[■□◆▶【]/.test(l); }

  function hasPhone(t) {
    return /(0\d{1,2}[-\s.]?[\d×*]{3,4}[-\s.][\d×*]{4})/.test(t) ||
      /내선\s?\d{2,5}/.test(t) || /[A-Za-z0-9._%+×*-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/.test(t);
  }

  function hasRole(t) {
    return /(팀장|과장|실장|부장|차장|대리|주무관|사무관|서기관|원장|부원장|진료부장|매니저|간사|전문위원|담당자?|실무자|소장|센터장|팀|과|부|실|원|협회|협의회|기관|업체|은행)/.test(t);
  }

  function findDue(text) {
    var m, y = TODAY.getFullYear();
    if ((m = text.match(/(20\d{2})\s*[.\-／\/년]\s*(\d{1,2})\s*[.\-／\/월]\s*(\d{1,2})\s*일?/))) {
      return mkDate(+m[1], +m[2], +m[3]);
    }
    if ((m = text.match(/(\d{1,2})\s*월\s*(\d{1,2})\s*일/))) return roll(+m[1], +m[2]);
    if ((m = text.match(/(\d{1,2})\s*월\s*(\d)\s*주/))) {
      var wk = clamp((+m[2] - 1) * 7 + 3, 1, 28);
      return roll(+m[1], wk);
    }
    if ((m = text.match(/(\d{1,2})\s*월\s*(초|중순|중|말|첫째\s?주|마지막\s?주)/))) {
      var d = { '초': 5, '중': 15, '중순': 15, '말': -1, '첫째주': 4, '마지막주': -3 }[m[2].replace(/\s/g, '')];
      if (d === -1) return new Date(y, +m[1], 0);
      if (d === -3) return new Date(y, +m[1], 0 - 2);
      return roll(+m[1], d);
    }
    if ((m = text.match(/\b(\d{1,2})\s*[\/.]\s*(\d{1,2})\b/)) && +m[1] <= 12) {
      return roll(+m[1], +m[2]);
    }
    if (/이번\s?주|금주/.test(text)) return new Date(TODAY.getTime() + (5 - TODAY.getDay() + 7) % 7 * DAY);
    if (/다음\s?주/.test(text)) return new Date(TODAY.getTime() + 7 * DAY);
    if (/오늘|금일/.test(text)) return new Date(TODAY);
    if (/내일|명일/.test(text)) return new Date(TODAY.getTime() + DAY);
    return null;
  }

  function mkDate(y, m, d) {
    var dt = new Date(y, m - 1, d);
    return isNaN(dt.getTime()) ? null : dt;
  }

  // 연도가 없는 날짜: 이미 20일 이상 지난 날짜면 다음 해로 본다
  function roll(m, d) {
    var dt = mkDate(TODAY.getFullYear(), m, d);
    if (!dt) return null;
    if (dt.getTime() < TODAY.getTime() - 20 * DAY) dt = mkDate(TODAY.getFullYear() + 1, m, d);
    return dt;
  }

  function ddayOf(due) { return due ? Math.round((due.getTime() - TODAY.getTime()) / DAY) : null; }

  function priorityOf(text, dday) {
    var p = 0;
    if (/(긴급|즉시|오늘\s?중|당일|최우선|ASAP|위기|중단)/i.test(text)) p += 2;
    if (/(원장|원무팀장|과장|부시장|시의회|감사|민원|언론|법원)/.test(text)) p += 1;
    if (dday !== null && dday !== undefined) {
      if (dday <= 3) p += 3;
      else if (dday <= 7) p += 2;
      else if (dday <= 14) p += 1;
    }
    if (/(진행률|진행\s?중|완료\s?임박)/.test(text)) p += 1;
    return p >= 3 ? '상' : (p >= 2 ? '중' : '하');
  }

  var TITLES = /(팀장|과장|실장|부장|차장|대리|주무관|사무관|서기관|원장|부원장|매니저|간사|전문위원|담당자?|소장|센터장|실무자|주임|계장)/;
  var ORG_TAIL = /(팀|과|부|실|원|청|소|회|처|국|센터|기관|업체|은행|병원|협의회|위원회|사업소)$/;

  function parseContact(text) {
    var phone = (text.match(/0\d{1,2}[-\s.]?[\d×*]{3,4}[-\s.][\d×*]{4}/g) || []).slice(0, 2);
    var ext = (text.match(/내선\s?(\d{2,5})/) || [])[1];
    var email = (text.match(/[A-Za-z0-9._%+×*-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/) || [])[0];
    var note = ((text.match(/\(([^)]{2,60})\)/) || [])[1] || '').trim();
    if (ext && note && note.replace(/\s/g, '').indexOf(String(ext)) >= 0 && note.length < 12) note = '';

    var head = text
      .replace(/\([^)]*\)/g, ' ')
      .replace(/0\d{1,2}[-\s.]?[\d×*]{3,4}[-\s.][\d×*]{4}/g, ' ')
      .replace(/내선\s?\d{2,5}/g, ' ')
      .replace(/[A-Za-z0-9._%+×*-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g, ' ')
      .replace(/\d[\d\-]{5,}/g, ' ')
      .replace(/[\/,·|:]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    var toks = head.split(' ').filter(Boolean);
    var role = '', name = '', org = '';
    var acct = /계좌|입금/.test(text) ? ((text.match(/[\d×*][\d\-×* ]{5,}/) || [])[0] || '').trim() : '';
    var titleIdx = -1, tk = '';
    for (var i = 0; i < toks.length; i++) {
      var mm = toks[i].match(TITLES);
      if (mm) { titleIdx = i; tk = toks[i]; break; }
    }

    if (titleIdx >= 0) {
      var m = tk.match(TITLES);
      var stem = tk.replace(TITLES, '');
      role = (stem ? tk : m[0]);
      // 이름: 직위 앞/뒤의 2~4자 한글 토큰
      var near = [toks[titleIdx - 1], toks[titleIdx + 1]];
      for (var j = 0; j < near.length; j++) {
        var c = near[j];
        if (!c) continue;
        if (!/^[가-힣○]{2,4}$/.test(c)) continue;
        if (TITLES.test(c) || ORG_TAIL.test(c)) continue;
        name = c; break;
      }
      if (!org) {
        if (name) {
          var ni = toks.indexOf(name);
          for (var b = ni - 1; b >= 0; b--) {
            var pre = toks[b];
            if (pre === tk) continue;
            if (TITLES.test(pre)) continue;
            if (ORG_TAIL.test(pre)) { org = pre; break; }
            if (pre.length >= 2) { org = pre; break; }
          }
        }
        if (!org) {
          for (var k = 0; k < toks.length; k++) {
            if (k === titleIdx || toks[k] === name) continue;
            if (ORG_TAIL.test(toks[k])) { org = toks[k]; break; }
          }
        }
      }
    } else {
      role = acct ? '계좌·정산' : (head.length <= 26 ? head : trunc(head, 26));
      if (acct) note = note || head;
    }

    return {
      name: name, role: role, org: org, phone: phone.join(' / '),
      ext: ext ? '내선 ' + ext : '', email: email || '', note: note || '',
      acct: acct, raw: text
    };
  }

  function classify(text, htype, srcName, heading) {
    var t = text.trim();
    if (t.length < 4) return null;
    var due = null;
    if (RE.task.test(t) || /\d/.test(t)) due = findDue(t);
    var isContactEntry = hasPhone(t) && !RE.arrow.test(t) && t.length < 120 &&
      (hasRole(t) || htype === 'contact' || /(계좌|은행|입금)/.test(t));

    var type;
    if (isContactEntry && htype !== 'risk' && !/말\s?것|금지/.test(t)) type = 'contact';
    else if (htype !== 'info') {
      type = htype;
      if (htype === 'task' && !due && /^(매일|매주|매월|매달|매년|매분기)/.test(t)) type = 'routine';
    } else if (/(요약|개요|소개|현황|구성|업무\s?개요)/.test(heading || '') && !due) {
      // '업무 개요' 아래 문장은 담당 업무 설명문으로 본다
      type = 'info';
    } else if (RE.risk.test(t)) type = 'risk';
    else if (RE.faq.test(t)) type = 'faq';
    else if (RE.routine.test(t)) type = 'routine';
    else if (due || RE.task.test(t)) type = 'task';
    else type = 'info';

    var item = {
      id: uid('i'), type: type, text: t, source: srcName || '',
      due: due, dday: ddayOf(due), priority: priorityOf(t, ddayOf(due)),
      cadence: '', next: null
    };
    if (type === 'routine') {
      var c = routineCadence(t);
      item.cadence = c.label; item.cadenceKey = c.key; item.next = c.next;
    }
    if (type === 'contact') item.contact = parseContact(t);
    if (type === 'risk') item.level = /(개인정보|주민|반출|유출|금지|법|청탁|처벌|감사|징계|사고|위약)/.test(t) ? 'high' : 'mid';
    if (type === 'faq') {
      var parts = t.split(/\s*(?:→|->|⇒|▶)\s*/);
      if (parts.length >= 2) { item.q = parts[0].replace(/[.。]$/, ''); item.a = parts.slice(1).join(' '); }
      else { item.q = trunc(t.replace(/[.。]$/, ''), 46); item.a = t; }
    }
    return item;
  }

  var WEEKDAY = { '일': 0, '월': 1, '화': 2, '수': 3, '목': 4, '금': 5, '토': 6 };
  function routineCadence(t) {
    var m;
    if (/매일|매\s?일|일일/.test(t)) return { key: 'daily', label: '매일', next: new Date(TODAY) };
    if ((m = t.match(/매주\s?([월화수목금토일])요일/))) {
      var wd = WEEKDAY[m[1]];
      var diff = (wd - TODAY.getDay() + 7) % 7;
      return { key: 'weekly', label: '매주 ' + m[1] + '요일', next: new Date(TODAY.getTime() + diff * DAY) };
    }
    if (/매주/.test(t)) return { key: 'weekly', label: '매주', next: null };
    if ((m = t.match(/매월\s?(\d{1,2})\s?일/))) {
      var day = +m[1];
      var d = mkDate(TODAY.getFullYear(), TODAY.getMonth() + 1, day);
      if (d.getTime() < TODAY.getTime()) d = mkDate(TODAY.getFullYear(), TODAY.getMonth() + 2, day);
      return { key: 'monthly', label: '매월 ' + day + '일', next: d, dom: day };
    }
    if (/매월\s?말|매달\s?말/.test(t)) {
      var last = new Date(TODAY.getFullYear(), TODAY.getMonth() + 1, 0);
      if (last.getTime() < TODAY.getTime()) last = new Date(TODAY.getFullYear(), TODAY.getMonth() + 2, 0);
      return { key: 'monthly', label: '매월 말일', next: last, dom: 'last' };
    }
    if (/매월|매달|월간/.test(t)) return { key: 'monthly', label: '매월', next: null };
    if (/매분기|분기별/.test(t)) return { key: 'quarterly', label: '매분기', next: null };
    if (/매년|연간|매\s?년/.test(t)) return { key: 'yearly', label: '매년', next: null };
    if (/반기/.test(t)) return { key: 'half', label: '매반기', next: null };
    return { key: 'etc', label: '정기', next: null };
  }

  function splitCSV(text) {
    var lines = text.replace(/\r/g, '').split('\n').filter(function (l) { return l.trim(); });
    if (lines.length < 2) return text;
    var sep = lines[0].indexOf(',') >= 0 ? ',' : (lines[0].indexOf('\t') >= 0 ? '\t' : null);
    if (!sep) return text;
    var head = lines[0].split(sep).map(function (h) { return h.trim().replace(/^"|"$/g, ''); });
    if (head.length < 2) return text;
    var out = [];
    for (var i = 1; i < lines.length; i++) {
      var cells = lines[i].split(sep).map(function (c) { return c.trim().replace(/^"|"$/g, ''); });
      var pairs = [];
      for (var j = 0; j < head.length; j++) {
        if (cells[j]) pairs.push(head[j] + ': ' + cells[j]);
      }
      if (pairs.length) out.push('- ' + pairs.join(' / '));
    }
    return out.length ? out.join('\n') : text;
  }

  function absorbMeta(line) {
    var m;
    if (!state.meta.from && (m = line.match(/(?:작성자|인계자|담당자)\s*[:：]\s*([가-힣○]{2,4})/))) state.meta.from = m[1];
    if (!state.meta.to && (m = line.match(/인수자\s*[:：]\s*([가-힣○]{2,4})/))) {
      if (!/미정/.test(m[1])) state.meta.to = m[1];
    }
    if ((!state.meta.date || state.meta.dateAuto) &&
      (m = line.match(/(?:인계일|인계\s?예정일|작성일)\s*[:：]\s*(\d{4})[.\-\/]\s?(\d{1,2})[.\-\/]\s?(\d{1,2})/))) {
      state.meta.date = m[1] + '-' + pad2(+m[2]) + '-' + pad2(+m[3]);
      state.meta.dateAuto = false;
    }
    if (!state.meta.org && (m = line.match(/^(?:기관|부서|소속)\s*[:：]\s*(.{2,40})$/))) state.meta.org = m[1].trim();
  }

  function parseSources() {
    var items = [];
    var seen = {};
    state.sources.forEach(function (src) {
      var text = processedText(src);
      var heading = '';
      var htype = 'info';
      text.replace(/\r/g, '').split('\n').forEach(function (line) {
        var raw = line.trim();
        if (!raw) return;
        if (isHeading(raw)) {
          heading = cleanLine(raw);
          htype = headingType(heading);
          return;
        }
        var t = cleanLine(raw);
        if (t.length < 4) return;
        if (/^[-=_*]{3,}$/.test(t)) return;
        // 문서 머리말(작성자·인계자·인수자·인계일)은 항목이 아니라 기본 정보로 흡수한다
        if (/^(작성자|인계자|인수자|인계일|작성일|담당자|소속|부서|기관)\s*[:：]/.test(t)) {
          absorbMeta(t);
          return;
        }
        var key = t.replace(/\s/g, '').slice(0, 60);
        if (seen[key]) return;
        var it = classify(t, htype, src.name, heading);
        if (!it) return;
        it.heading = heading;
        seen[key] = 1;
        items.push(it);
      });
    });
    return items;
  }

  /* ============================================================
     3. 인수인계서 조립
     ============================================================ */
  function buildDoc() {
    var items = parseSources();
    var tasks = items.filter(function (i) { return i.type === 'task'; });
    var routines = items.filter(function (i) { return i.type === 'routine'; });
    var contacts = items.filter(function (i) { return i.type === 'contact'; });
    var faqs = items.filter(function (i) { return i.type === 'faq'; });
    var risks = items.filter(function (i) { return i.type === 'risk'; });
    var infos = items.filter(function (i) { return i.type === 'info'; });

    var rank = { '상': 0, '중': 1, '하': 2 };
    tasks.sort(function (a, b) {
      var ra = rank[a.priority], rb = rank[b.priority];
      if (ra !== rb) return ra - rb;
      var da = a.dday === null ? 9999 : a.dday, db = b.dday === null ? 9999 : b.dday;
      return da - db;
    });
    contacts = contacts.slice(0, 12);
    faqs = faqs.slice(0, 10);
    risks.sort(function (a, b) { return (a.level === 'high' ? 0 : 1) - (b.level === 'high' ? 0 : 1); });
    risks = risks.slice(0, 12);

    // 요약: '업무 개요'류 문장을 우선, 없으면 전체 정보 문장
    var overview = infos.filter(function (i) { return /(요약|개요|소개|현황|구성)/.test(i.heading || ''); });
    var summaryBullets = (overview.length ? overview : infos).slice(0, 5).map(function (i) { return i.text; });
    if (!summaryBullets.length) {
      summaryBullets = tasks.slice(0, 3).map(function (i) { return i.text; });
    }

    var urgency = tasks.filter(function (t) { return t.dday !== null && t.dday <= 7; }).length;

    var doc = {
      meta: state.meta,
      generatedAt: new Date(),
      items: items,
      summary: summaryBullets,
      tasks: tasks,
      routines: routines,
      contacts: contacts,
      faq: faqs,
      risks: risks,
      infos: infos,
      stats: {
        total: items.length,
        tasks: tasks.length,
        urgent: urgency,
        routines: routines.length,
        contacts: contacts.length,
        faq: faqs.length,
        risks: risks.length
      },
      onboarding: buildOnboarding(tasks, routines, contacts, faqs, risks, infos)
    };
    doc.score = scoreDoc(doc);
    return doc;
  }

  function buildOnboarding(tasks, routines, contacts, faqs, risks, infos) {
    var pwd = risks.concat(infos).filter(function (i) { return /(계정|비밀번호|권한|시스템|프로그램)/.test(i.text); })[0];
    var files = infos.concat(risks).filter(function (i) { return /(공유드라이브|폴더|서버|문서함|보관|자료실)/.test(i.text); })[0];
    var line = risks.filter(function (i) { return /(결재선|보고|직보)/.test(i.text); })[0];
    var cs = contacts.map(function (c) { return c.contact.name || c.contact.role || c.text; }).slice(0, 3);

    var days = [
      { n: 1, title: '자리·계정·자료 파악', items: [
        '출입증·PC·전화(내선) 배정 확인, 업무용 메일 서명 변경',
        pwd ? '계정·권한 확보: ' + trunc(pwd.text, 70) : '업무 시스템 계정·권한 신청 (정보화 담당자 문의)',
        files ? '자료 위치 확인: ' + trunc(files.text, 70) : '업무 자료 보관 위치(공유드라이브) 확인',
        '인수인계서 ①~⑦ 전체 1회 통독'
      ] },
      { n: 2, title: '사람·보고체계 익히기', items: [
        cs.length ? '핵심 이해관계자 인사: ' + cs.join(', ') : '핵심 이해관계자 인사 일정 잡기',
        line ? '보고·결재선 확인: ' + trunc(line.text, 70) : '상급자·결재선(보고 순서) 확인',
        '상급자 면담: 1주일 우선순위 조율'
      ] },
      { n: 3, title: '급한 과제 착수', items: tasks.slice(0, 3).map(function (t) {
        return (t.dday !== null ? 'D-' + t.dday + ' ' : '') + trunc(t.text, 80);
      }) },
      { n: 4, title: '반복 업무 첫 수행', items: routines.slice(0, 3).map(function (r) {
        var t = r.text;
        if (t.indexOf(r.cadence) === 0) return trunc(t, 80);
        return '[' + r.cadence + '] ' + trunc(t, 80);
      }) },
      { n: 5, title: '단골 문제 대응 익히기', items: faqs.slice(0, 3).map(function (f) {
        return 'Q. ' + trunc(f.q, 60);
      }) },
      { n: 6, title: '리스크·규정 숙지', items: risks.slice(0, 3).map(function (r) {
        return trunc(r.text, 90);
      }) },
      { n: 7, title: '첫 주 점검·질문 정리', items: [
        '미완료 과제 ' + tasks.length + '건 진행 상태 재확인',
        '인계자에게 물어볼 질문 목록 정리(문서에 없는 내용)',
        '다음 주 우선순위를 상급자와 합의'
      ] }
    ];

    days.forEach(function (d) {
      d.items = d.items.filter(function (x) { return x && String(x).trim(); });
      if (!d.items.length) d.items = ['해당 자료 없음 — 직접 확인 필요'];
      d.items = d.items.map(function (t, i) {
        return { key: 'd' + d.n + '-' + i, text: String(t), done: !!lsGet('onb.' + hashStr(t), false) };
      });
    });
    return days;
  }

  function hashStr(s) {
    var h = 0;
    for (var i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; }
    return Math.abs(h).toString(36).slice(0, 8);
  }

  /* ============================================================
     4. 점수·누락 점검
     ============================================================ */
  var CHECKS = [
    { code: 'pwd', label: '계정·비밀번호 인수 방법', hint: '시스템 계정, 비밀번호 전달 방식(문서화 금지 여부)을 적어 두세요.', test: function (d) { return has(d, /(비밀번호|패스워드|계정|권한|ID\s?발급)/); } },
    { code: 'approval', label: '결재선·보고 체계', hint: '누구에게 어떤 순서로 보고·결재하는지가 없으면 후임자가 첫 주에 막힙니다.', test: function (d) { return has(d, /(결재|보고\s?체계|직보|상신|보고\s?라인|결재선)/); } },
    { code: 'emergency', label: '비상연락처(야간·휴일)', hint: '야간·휴일 당직, 사고 시 연락처를 추가하세요.', test: function (d) { return has(d, /(당직|비상|야간|휴일|상황실)/); } },
    { code: 'files', label: '자료 보관 위치', hint: '공유드라이브·폴더 경로를 적어 주면 인수자가 바로 찾습니다.', test: function (d) { return has(d, /(공유드라이브|폴더|서버|문서함|보관함|자료실|나스|NAS)/i); } },
    { code: 'deadline', label: '마감일이 있는 과제', hint: '과제에 마감일(예: 12월 5일까지)을 붙이면 D-Day로 자동 정렬됩니다.', test: function (d) { return d.tasks.some(function (t) { return t.dday !== null; }); } },
    { code: 'budget', label: '예산·계약 담당', hint: '예산 집행·계약 담당자와 한도를 적어 두세요.', test: function (d) { return has(d, /(예산|계약|정산|집행|용역)/); } },
    { code: 'law', label: '법령·감사 리스크', hint: '개인정보·청탁금지·감사 대비 등 규정 위반 소지가 있는 업무를 표시하세요.', test: function (d) { return has(d, /(법|규정|감사|개인정보|청탁|보안)/); } },
    { code: 'contact', label: '이해관계자 연락처 2명 이상', hint: '협업 부서·외부기관 담당자를 2명 이상 적어 주세요.', test: function (d) { return d.contacts.length >= 2; } },
    { code: 'successor', label: '인수자 지정', hint: '기본 정보(0번)에 인수자를 입력하면 인계 완료도를 정확히 볼 수 있습니다.', test: function (d) { return !!d.meta.to; } },
    { code: 'handover_date', label: '인계일 지정', hint: '인계일을 정하면 문서 머리말에 표시됩니다.', test: function (d) { return !!d.meta.date; } },
    { code: 'memo', label: '인계 메모(노하우)', hint: '문서에 없는 요령·주의점을 마지막에 남겨 주세요.', test: function (d) { return has(d, /(메모|노하우|요령|팁|참고|유의사항)/); } }
  ];

  function has(doc, re) {
    return doc.items.some(function (i) { return re.test(i.text); });
  }

  function scoreDoc(doc) {
    var sections = SECTIONS.map(function (s) {
      var n = 0;
      if (s.key === 'onboarding') n = doc.onboarding.length;
      else n = (doc[s.key] || []).length;
      var ratio = clamp(n / s.target, 0, 1);
      return { key: s.key, label: s.label, weight: s.weight, n: n, got: s.weight * ratio };
    });
    var base = sections.reduce(function (a, b) { return a + b.got; }, 0);
    var checks = CHECKS.map(function (c) {
      var ok = false;
      try { ok = !!c.test(doc); } catch (e) { ok = false; }
      return { code: c.code, label: c.label, hint: c.hint, ok: ok };
    });
    var failCount = checks.filter(function (c) { return !c.ok; }).length;
    var penalty = Math.min(22, failCount * 3);
    var score = clamp(Math.round(base - penalty), 0, 100);
    return { score: score, base: Math.round(base), sections: sections, checks: checks, failCount: failCount };
  }

  /* ============================================================
     5. 렌더링
     ============================================================ */
  function renderSources() {
    var list = $('#sourceList');
    $('#sourceCount').textContent = state.sources.length;
    if (!state.sources.length) {
      list.innerHTML = '<li class="empty">아직 자료가 없습니다. 샘플을 눌러 바로 체험해 보세요.</li>';
    } else {
      list.innerHTML = state.sources.map(function (s) {
        var n = (s.findings || []).length;
        return '<li class="src-item" data-id="' + s.id + '">' +
          '<span class="ico">' + (s.kind === 'file' ? '📄' : (s.kind === 'sample' ? '★' : '✎')) + '</span>' +
          '<span class="body"><span class="nm">' + esc(s.name) + '</span>' +
          '<span class="mt">' + s.raw.length.toLocaleString() + '자 · ' + (n ? '개인정보 ' + n + '건 마스킹' : '민감정보 없음') + '</span></span>' +
          '<button type="button" class="rm" aria-label="삭제" data-rm="' + s.id + '">✕</button></li>';
      }).join('');
    }
    $('#btnClearSources').style.visibility = state.sources.length ? 'visible' : 'hidden';
  }

  function renderMask() {
    var sums = allFindings();
    var keys = Object.keys(sums);
    var total = keys.reduce(function (a, k) { return a + sums[k]; }, 0);
    var el = $('#maskSummary');
    var det = $('#maskDetails');

    if (!state.sources.length) {
      el.innerHTML = '<span class="mchip ok">자료를 넣으면 자동으로 점검합니다</span>';
      det.hidden = true;
      return;
    }
    if (!total) {
      el.innerHTML = '<span class="mchip ok">✓ 민감정보 0건 — 그대로 써도 됩니다</span>';
      det.hidden = true;
    } else {
      var LAB = { rrn: '주민번호', phone: '전화번호', email: '이메일', account: '계좌번호', card: '카드번호', bizno: '사업자번호' };
      el.innerHTML = keys.map(function (k) {
        var risk = (PII.filter(function (p) { return p.type === k; })[0] || {}).risk || 'mid';
        return '<span class="mchip ' + (risk === 'high' ? 'high' : 'mid') + '">' + LAB[k] + ' ' + sums[k] + '건</span>';
      }).join('') + '<span class="mchip ' + (state.maskOn ? 'ok' : 'high') + '">' +
        (state.maskOn ? '마스킹 적용됨' : '⚠ 마스킹 꺼짐') + '</span>';

      var rows = [];
      state.sources.forEach(function (s) {
        (s.findings || []).forEach(function (f) { rows.push(f); });
      });
      det.hidden = false;
      $('#maskList').innerHTML = rows.slice(0, 80).map(function (f) {
        return '<li><span class="ty">' + esc(f.label) + '</span><span class="vv">' + esc(f.masked) + '</span></li>';
      }).join('') + (rows.length > 80 ? '<li class="hint">외 ' + (rows.length - 80) + '건</li>' : '');
    }
  }

  function renderDoc() {
    var d = state.doc;
    if (!d) return;
    $('#emptyState').hidden = true;
    $('#docRoot').hidden = false;
    $('#docToolbar').hidden = false;
    $('#scoreCard').hidden = false;
    $('#qaFab').hidden = false;

    var m = d.meta;
    var title = (m.org ? m.org : '업무') + ' 인수인계서';
    var headBits = [];
    if (m.from) headBits.push('인계자 <b>' + esc(m.from) + '</b>');
    if (m.to) headBits.push('인수자 <b>' + esc(m.to) + '</b>');
    if (m.date) headBits.push('인계일 <b>' + esc(fmtDateStr(m.date)) + '</b>');

    var html = '';
    html += '<div class="doc-head">' +
      '<p class="kicker">업무 인수인계서 · 이어줌 AI</p>' +
      '<h2>' + esc(title) + '</h2>' +
      '<div class="meta">' + (headBits.length ? headBits.map(function (x) { return '<span>' + x + '</span>'; }).join('') : '<span>기본 정보는 왼쪽 0번에서 입력할 수 있습니다</span>') + '</div>' +
      '<div class="badges">' +
      (state.aiUsedBy ? '<span class="badge-ai">AI 정밀 분석 · ' + esc(state.aiUsedBy) + '</span>' : '<span class="badge-ai">내장 엔진 · 브라우저 처리</span>') +
      '<span class="badge-time">' + fmtD(d.generatedAt) + ' 생성 · 자료 ' + state.sources.length + '건 · 문장 ' + d.stats.total + '개 분석</span>' +
      '</div></div>';

    /* ① 요약 */
    var kpis = '<div class="kpis">' +
      '<div class="kpi"><b>' + d.stats.tasks + '</b><span>진행·미완료 과제</span></div>' +
      '<div class="kpi urgent"><b>' + d.stats.urgent + '</b><span>7일 내 마감</span></div>' +
      '<div class="kpi"><b>' + d.stats.routines + '</b><span>반복 루틴</span></div>' +
      '<div class="kpi"><b>' + d.stats.contacts + '</b><span>이해관계자</span></div>' +
      '</div>';
    var sumHtml = d.summary.length
      ? '<ul class="sum-list">' + d.summary.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ul>'
      : '<p class="none">자료에 업무 개요 문장이 없습니다. “## 업무 개요” 아래에 담당 업무를 1~2줄 적어 주세요.</p>';
    html += sec('s1', '①', '핵심 업무 요약', d.summary.length + '개 문장', sumHtml + kpis);

    /* ② 과제 */
    var taskHtml;
    if (!d.tasks.length) {
      taskHtml = '<p class="none">진행 중인 과제를 찾지 못했습니다.</p><div class="addhint">“12월 5일까지 ○○ 제출”, “△△ 결재 상신 예정”처럼 <b>할 일 + 마감일</b>을 한 줄로 적으면 D-Day와 우선순위가 자동으로 붙습니다.</div>';
    } else {
      taskHtml = d.tasks.map(function (t) {
        var dd = t.dday;
        var dcls = 'dday', dtxt = '기한 미지정';
        if (dd !== null) {
          if (dd < 0) { dcls += ' done'; dtxt = 'D+' + Math.abs(dd) + ' 경과'; }
          else if (dd <= 3) { dcls += ' hot'; dtxt = dd === 0 ? 'D-DAY' : 'D-' + dd; }
          else if (dd <= 7) { dcls += ' soon'; dtxt = 'D-' + dd; }
          else { dcls += ' calm'; dtxt = 'D-' + dd; }
        }
        return '<div class="task">' +
          '<span class="pri ' + t.priority + '">' + t.priority + '</span>' +
          '<div><div class="txt">' + esc(t.text) + '</div>' +
          '<div class="sub">' + (t.due ? '<span>마감 ' + fmtD(t.due) + '</span>' : '') +
          '<span class="srcchip">' + esc(t.source) + '</span></div></div>' +
          '<span class="' + dcls + '">' + dtxt + '</span></div>';
      }).join('');
    }
    html += sec('s2', '②', '진행 중·미완료 과제', d.tasks.length + '건 · 마감 임박순', taskHtml);

    /* ③ 루틴 + 캘린더 */
    var routineHtml = '';
    if (!d.routines.length) {
      routineHtml = '<p class="none">반복 업무를 찾지 못했습니다.</p><div class="addhint">“매월 5일까지 ○○ 보고”, “매주 월요일 회의”처럼 <b>주기</b>를 넣으면 캘린더에 자동 배치됩니다.</div>';
    } else {
      var order = ['daily', 'weekly', 'monthly', 'quarterly', 'half', 'yearly', 'etc'];
      var labels = { daily: '매일', weekly: '매주', monthly: '매월', quarterly: '매분기', half: '반기', yearly: '매년', etc: '기타 정기' };
      routineHtml = order.map(function (k) {
        var list = d.routines.filter(function (r) { return r.cadenceKey === k; });
        if (!list.length) return '';
        return '<div class="rgroup"><h4><span class="tag">' + labels[k] + '</span> ' + list.length + '건</h4>' +
          list.map(function (r) {
            return '<div class="rtn"><span class="dot"></span><span class="when">' + esc(r.cadence) + '</span>' +
              '<span style="flex:1">' + esc(r.text) + '</span>' +
              (r.next ? '<span class="next">다음 ' + fmtD(r.next) + '</span>' : '') + '</div>';
          }).join('') + '</div>';
      }).join('');
      routineHtml += renderCalendar(d);
    }
    html += sec('s3', '③', '반복 루틴 캘린더', d.routines.length + '건 · 이번 달 일정', routineHtml);

    /* ④ 연락처 */
    var contactHtml;
    if (!d.contacts.length) {
      contactHtml = '<p class="none">연락처를 찾지 못했습니다.</p><div class="addhint">“부서·직위 이름 010-0000-0000” 형식으로 적으면 카드로 정리되고, 번호는 자동으로 가려집니다.</div>';
    } else {
      contactHtml = '<div class="contact-grid">' + d.contacts.map(function (c) {
        var k = c.contact;
        var nm = k.name ? esc(k.name) : esc(k.role || '담당자');
        var role = k.name ? esc((k.org ? k.org + ' ' : '') + (k.role || '')) : (k.acct ? '계좌 정보' : (k.org ? esc(k.org) : '연락처'));
        var lines = '';
        if (k.phone) lines += '<div class="line"><span class="k">전화</span><span class="tel">' + esc(k.phone) + '</span></div>';
        if (k.acct) lines += '<div class="line"><span class="k">계좌</span><span class="tel">' + esc(k.acct) + '</span></div>';
        if (k.ext) lines += '<div class="line"><span class="k">내선</span><span class="tel">' + esc(k.ext.replace('내선 ', '')) + '</span></div>';
        if (k.email) lines += '<div class="line"><span class="k">메일</span><span>' + esc(k.email) + '</span></div>';
        var noteTxt = k.note || '';
        return '<div class="contact"><div class="role">' + role + '</div>' +
          '<div class="nm">' + nm + '</div>' + lines +
          (noteTxt ? '<div class="note">' + esc(noteTxt) + '</div>' : '') + '</div>';
      }).join('') + '</div>';
    }
    html += sec('s4', '④', '이해관계자·비상연락망', d.contacts.length + '명', contactHtml);

    /* ⑤ FAQ */
    var faqHtml;
    if (!d.faq.length) {
      faqHtml = '<p class="none">자주 겪는 문제가 정리되지 않았습니다.</p><div class="addhint">“○○ 오류 → △△ 조치” 형태로 적으면 질문/답 카드로 자동 변환됩니다.</div>';
    } else {
      faqHtml = d.faq.map(function (f, i) {
        return '<details class="faq" open><summary>' + esc(f.q) + '</summary><div class="ans">' + esc(f.a) + '</div></details>';
      }).join('');
    }
    html += sec('s5', '⑤', '트러블슈팅 FAQ', d.faq.length + '문항', faqHtml);

    /* ⑥ 온보딩 */
    var doneN = 0, allN = 0;
    d.onboarding.forEach(function (day) { day.items.forEach(function (it) { allN++; if (it.done) doneN++; }); });
    var onbHtml = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:9px">' +
      '<span class="hint">체크 상태는 이 브라우저에 저장됩니다.</span>' +
      '<span class="onb-progress">완료 ' + doneN + ' / ' + allN + '</span></div>' +
      d.onboarding.map(function (day) {
        return '<div class="onb-day"><div class="dh"><span class="n">DAY ' + day.n + '</span><b>' + esc(day.title) + '</b></div>' +
          '<ul class="onb-items">' + day.items.map(function (it) {
            return '<li class="' + (it.done ? 'done' : '') + '"><input type="checkbox" data-onb="' + esc(hashStr(it.text)) + '"' + (it.done ? ' checked' : '') + '>' +
              '<span class="lb">' + esc(it.text) + '</span></li>';
          }).join('') + '</ul></div>';
      }).join('');
    html += sec('s6', '⑥', '인수자 첫 7일 온보딩', '체크리스트', onbHtml);

    /* ⑦ 리스크 */
    var riskHtml;
    if (!d.risks.length) {
      riskHtml = '<p class="none">주의사항이 확인되지 않았습니다.</p><div class="addhint">개인정보·감사·청탁금지 등 <b>하지 말아야 할 일</b>을 반드시 남겨 주세요. 인수인계 사고의 대부분이 여기서 납니다.</div>';
    } else {
      riskHtml = d.risks.map(function (r) {
        return '<div class="risk"><span class="ic">' + (r.level === 'high' ? '🚫' : '⚠️') + '</span>' +
          '<span><span class="lv ' + r.level + '">' + (r.level === 'high' ? '중대' : '주의') + '</span>' + esc(r.text) + '</span></div>';
      }).join('');
    }
    html += sec('s7', '⑦', '리스크·주의사항', d.risks.length + '건', riskHtml);

    html += '<p class="doc-foot">이 문서는 이어줌 AI가 투입 자료 ' + state.sources.length + '건을 분석해 자동 생성했습니다. ' +
      '개인정보 ' + (state.maskOn ? '는 마스킹된 상태' : '가 포함된 상태 — 배포 전 확인 필요') + '. 최종 내용은 인계자·인수자가 함께 확인하세요.</p>';

    $('#docRoot').innerHTML = html;
    renderScore(d.score);
    renderQaChips();
  }

  function sec(cls, no, title, cnt, body) {
    return '<section class="sec ' + cls + '"><div class="sec-head"><span class="sec-no">' + no + '</span>' +
      '<h3>' + title + '</h3><span class="cnt">' + esc(cnt) + '</span></div><div class="sec-body">' + body + '</div></section>';
  }

  function renderCalendar(d) {
    var y = TODAY.getFullYear(), mo = TODAY.getMonth();
    var first = new Date(y, mo, 1);
    var startDow = first.getDay();
    var lastDate = new Date(y, mo + 1, 0).getDate();
    var marks = {};
    d.tasks.forEach(function (t) {
      if (t.due && t.due.getMonth() === mo && t.due.getFullYear() === y) {
        marks[t.due.getDate()] = marks[t.due.getDate()] || [];
        marks[t.due.getDate()].push('t');
      }
    });
    d.routines.forEach(function (r) {
      if (typeof r.next === 'object' && r.next && r.next.getMonth() === mo && r.next.getFullYear() === y) {
        var dd = r.next.getDate();
        marks[dd] = marks[dd] || [];
        if (marks[dd].indexOf('r') < 0) marks[dd].push('r');
      } else if (r.dom && r.dom !== 'last' && r.dom <= lastDate) {
        marks[r.dom] = marks[r.dom] || [];
        if (marks[r.dom].indexOf('r') < 0) marks[r.dom].push('r');
      } else if (r.dom === 'last') {
        marks[lastDate] = marks[lastDate] || [];
        if (marks[lastDate].indexOf('r') < 0) marks[lastDate].push('r');
      }
    });

    var total = 0;
    var cells = '<div class="cal-dow">일</div><div class="cal-dow">월</div><div class="cal-dow">화</div><div class="cal-dow">수</div><div class="cal-dow">목</div><div class="cal-dow">금</div><div class="cal-dow">토</div>';
    for (var i = 0; i < startDow; i++) cells += '<div class="cal-cell out"></div>';
    for (var day = 1; day <= lastDate; day++) {
      var isToday = TODAY.getFullYear() === y && TODAY.getMonth() === mo && TODAY.getDate() === day;
      var dots = (marks[day] || []).map(function (k) { return '<i class="' + k + '"></i>'; }).join('');
      cells += '<div class="cal-cell' + (isToday ? ' today' : '') + '"><span class="d">' + day + '</span><div class="dots">' + dots + '</div></div>';
      total = startDow + day;
    }
    while (total % 7 !== 0) { cells += '<div class="cal-cell out"></div>'; total++; }
    return '<div class="cal"><div class="cal-head"><b>' + y + '년 ' + (mo + 1) + '월</b>' +
      '<div class="cal-legend"><span class="l1"><i></i>마감</span><span class="l2"><i></i>반복</span></div></div>' +
      '<div class="cal-grid">' + cells + '</div></div>';
  }

  function renderScore(sc) {
    var gauge = $('#gaugeFg');
    var deg = 314 * (1 - sc.score / 100);
    gauge.style.strokeDashoffset = deg;
    gauge.style.stroke = sc.score >= 80 ? '#0d9488' : (sc.score >= 60 ? '#2563eb' : (sc.score >= 40 ? '#c2740b' : '#d92d20'));
    $('#scoreNum').textContent = sc.score;
    $('#scoreTitle').textContent = sc.score >= 85 ? '인계 준비 완료' : (sc.score >= 70 ? '거의 다 됐어요' : (sc.score >= 50 ? '보완이 필요해요' : '자료가 더 필요해요'));
    $('#scoreSub').textContent = '구조 ' + sc.base + '점 − 누락 감점 ' + (sc.base - sc.score) + '점 · 남은 항목 ' + sc.failCount + '개';

    $('#scoreBars').innerHTML = sc.sections.map(function (s) {
      var pct = Math.round(clamp(s.n / (SECTIONS.filter(function (x) { return x.key === s.key; })[0].target), 0, 1) * 100);
      var cls = pct >= 100 ? 'ok' : (pct >= 50 ? '' : 'low');
      return '<div class="sbar ' + cls + '"><span>' + s.label.replace(' 캘린더', '').replace('·비상연락망', '') + '</span>' +
        '<span class="track"><span class="fill" style="width:' + pct + '%"></span></span><span>' + s.n + '</span></div>';
    }).join('');

    var fails = sc.checks.filter(function (c) { return !c.ok; });
    var piiTotal = 0;
    Object.keys(allFindings()).forEach(function (k) { piiTotal += allFindings()[k]; });
    if (!state.maskOn && piiTotal > 0) {
      fails = [{ label: '개인정보 ' + piiTotal + '건 노출', hint: '마스킹을 켜면 문서와 AI 전송에서 자동으로 가려집니다.' }].concat(fails);
    }
    if (!fails.length) {
      $('#scoreWarn').innerHTML = '<div class="warn-title" style="color:#0d9488">✓ 빠진 항목 없음</div><p class="allgood">인수자가 바로 시작할 수 있는 수준입니다.</p>';
    } else {
      $('#scoreWarn').innerHTML = '<div class="warn-title">⚠ 누락 항목 ' + fails.length + '개</div><ul class="warn-list">' +
        fails.slice(0, 6).map(function (c) {
          return '<li><span class="badge">누락</span><span>' + esc(c.label) + '<span class="hintx">' + esc(c.hint) + '</span></span></li>';
        }).join('') + (fails.length > 6 ? '<li><span class="badge">외</span><span>' + (fails.length - 6) + '개 더 있습니다</span></li>' : '') + '</ul>';
    }
  }

  /* ============================================================
     6. 후임자 Q&A
     ============================================================ */
  var STOP = ('그리고 그럼 그래서 하지만 있는 있는데 합니다 입니다 인가요 해서 에서 에는 하고 이고 라고 으로 로써 대한 대한데요 무엇 뭐가 어디 언제 누구 어떻게 알려줘 알려주세요 줄까요 해야 하나요 인지 어떤 무슨 좀 잘 좀더 지금 현재 여기 저기 우리 제가 네 예 아니요').split(/\s+/);

  function tokenize(q) {
    return String(q).toLowerCase()
      .replace(/[?!.,"'“”‘’()\[\]{}:;~…·]/g, ' ')
      .split(/\s+/)
      .filter(function (w) { return w.length >= 2 && STOP.indexOf(w) < 0; })
      .map(function (w) {
        return w.replace(/(은|는|이|가|을|를|의|에|에서|에게|한테|께|와|과|도|로|으로|까지|부터|만|랑|이랑|하고|보다|라고|나|이나|요|죠|까|나요|가요|인가요)$/g, '');
      })
      .filter(function (w) { return w.length >= 2; });
  }

  function qaUnits(d) {
    var u = [];
    d.summary.forEach(function (s) { u.push({ sec: '핵심 업무 요약', title: trunc(s, 40), text: s, kind: 'summary' }); });
    d.tasks.forEach(function (t) {
      u.push({
        sec: '진행 과제', kind: 'task', title: trunc(t.text, 40), text: t.text,
        extra: (t.dday !== null ? (t.dday < 0 ? '기한 ' + Math.abs(t.dday) + '일 경과' : 'D-' + t.dday) + ' · 마감 ' + fmtD(t.due) : '마감 미지정') + ' · 우선순위 ' + t.priority,
        obj: t
      });
    });
    d.routines.forEach(function (r) {
      u.push({ sec: '반복 루틴', kind: 'routine', title: trunc(r.text, 40), text: r.text, extra: r.cadence + (r.next ? ' · 다음 ' + fmtD(r.next) : ''), obj: r });
    });
    d.contacts.forEach(function (c) {
      u.push({
        sec: '연락처', kind: 'contact', title: (c.contact.name || c.contact.role || '연락처'), text: c.text,
        extra: [c.contact.phone, c.contact.ext, c.contact.email].filter(Boolean).join(' · '), obj: c
      });
    });
    d.faq.forEach(function (f) {
      u.push({ sec: '트러블슈팅', kind: 'faq', title: f.q, text: f.q + ' → ' + f.a, obj: f });
    });
    d.risks.forEach(function (r) {
      u.push({ sec: '리스크', kind: 'risk', title: trunc(r.text, 40), text: r.text, obj: r });
    });
    d.onboarding.forEach(function (day) {
      day.items.forEach(function (it) {
        u.push({ sec: '온보딩 DAY ' + day.n, kind: 'onb', title: day.title, text: it.text });
      });
    });
    d.infos.forEach(function (i) { u.push({ sec: '인계 메모', kind: 'info', title: trunc(i.text, 40), text: i.text }); });
    return u;
  }

  function answerQuestion(q) {
    var d = state.doc;
    if (!d) return null;
    var toks = tokenize(q);
    var units = qaUnits(d);
    var intent = {
      contact: /(연락|전화|번호|누구|담당자|비상)/.test(q) ? 2 : 1,
      task: /(마감|언제|일정|급한|우선|먼저|D-|까지|과제)/.test(q) ? 2 : 1,
      routine: /(매월|매주|매일|정기|반복|루틴)/.test(q) ? 2 : 1,
      risk: /(주의|위험|조심|금지|문제|리스크)/.test(q) ? 2 : 1,
      faq: /(오류|대응|어떻게|조치|방법|해결)/.test(q) ? 1.5 : 1,
      onb: /(처음|첫|시작|뭐부터|온보딩)/.test(q) ? 2 : 1
    };

    units.forEach(function (u) {
      var sc = 0;
      toks.forEach(function (t) {
        if (u.text.indexOf(t) >= 0) sc += 2 + Math.min(2, t.length / 2);
        if (u.title.indexOf(t) >= 0) sc += 1;
        if (u.extra && u.extra.indexOf(t) >= 0) sc += 0.5;
      });
      if (u.sec.indexOf('연락') >= 0) sc *= intent.contact;
      if (u.kind === 'task') sc *= intent.task * 1.15;
      if (u.kind === 'routine') sc *= intent.routine;
      if (u.kind === 'risk') sc *= intent.risk;
      if (u.kind === 'faq') sc *= intent.faq * 1.05;
      if (u.kind === 'onb') sc *= intent.onb * 0.8;
      if (u.kind === 'info' || u.kind === 'summary') sc *= 0.9;
      u.score = sc;
    });

    var found = units.filter(function (u) { return u.score > 0; }).sort(function (a, b) { return b.score - a.score; });

    // 인사·일반 질문
    if (!toks.length || /^(안녕|반가|고마|감사|누구세요|뭐 할|무엇을)/.test(q.trim())) {
      return {
        text: '안녕하세요. 인수인계서를 바탕으로 답해 드립니다. 아래처럼 물어보세요.\n· 오늘 가장 급한 일은?\n· 원무팀장 연락처 알려줘\n· 매월 해야 하는 일은?\n· ARS 멘트가 안 바뀌면?',
        ev: []
      };
    }

    if (!found.length) {
      var miss = /(비밀번호|패스워드|계정)/.test(q)
        ? '특히 비밀번호·계정은 문서에 남기지 않는 경우가 많습니다. 인수인계서에 “누구에게 직접 문의”만 적혀 있는지 확인하세요.'
        : '자료에 없는 내용은 인계자에게 직접 확인하는 것이 안전합니다. 질문 목록에 적어 두세요.';
      if (!/(급한|급해|우선|먼저|뭐부터|순서|오늘|이번\s?주)/.test(q)) {
        return { text: '인수인계서에는 그 내용이 없습니다.\n' + miss, ev: [] };
      }
    }

    // 우선순위·급한 일 질문은 마감 임박순으로 바로 답한다
    if (/(급한|급해|우선|먼저|뭐부터|순서|오늘|이번\s?주)/.test(q) && d.tasks.length) {
      var urgent = d.tasks.slice(0, 3);
      var ul = ['지금 우선순위는 이렇습니다.'];
      urgent.forEach(function (t, i) {
        ul.push((i + 1) + '. ' + (t.dday !== null ? (t.dday < 0 ? '기한경과 ' : 'D-' + t.dday + ' ') : '') + trunc(t.text, 80) + '  (우선순위 ' + t.priority + ')');
      });
      return {
        text: ul.join('\n'),
        ev: urgent.map(function (t) { return { sec: '진행 과제', text: trunc(t.text, 110) }; })
      };
    }

    // 목록형 질문: 상위 3개
    var listIntent = /(뭐뭐|목록|전부|모두|정리해|뭐가\s?있|무엇이\s?있|뭐부터)/.test(q) || toks.length <= 1;
    var top = found[0];
    if (intent.contact >= 2 && top.kind === 'contact') listIntent = false;
    var lines = [];
    var ev = [];

    if (listIntent && found.length > 1) {
      var picked = found.slice(0, 3);
      lines.push('인수인계서에서 찾은 내용입니다.');
      picked.forEach(function (u, i) {
        lines.push((i + 1) + '. ' + (u.kind === 'contact' ? u.sec + ' · ' + u.title : trunc(u.text, 90)) + (u.extra ? '  (' + u.extra + ')' : ''));
      });
      ev = picked.map(function (u) { return { sec: u.sec, text: trunc(u.text, 110) }; });
    } else {
      if (top.kind === 'contact') {
        var c = top.obj.contact;
        lines.push((c.name || c.role || '담당자') + ' 연락처입니다.');
        if (c.role) lines.push('· 소속·직위: ' + c.role);
        if (c.phone) lines.push('· 전화: ' + c.phone);
        if (c.ext) lines.push('· ' + c.ext);
        if (c.email) lines.push('· 메일: ' + c.email);
        if (c.note) lines.push('· 참고: ' + c.note);
      } else if (top.kind === 'task') {
        var t = top.obj;
        lines.push(trunc(t.text, 120));
        lines.push('· ' + (t.dday !== null ? (t.dday < 0 ? '기한이 ' + Math.abs(t.dday) + '일 지났습니다. 즉시 확인이 필요합니다.' : 'D-' + t.dday + ' (마감 ' + fmtD(t.due) + ')') : '마감일이 정해져 있지 않습니다. 상급자와 일정을 정하세요.') + ' · 우선순위 ' + t.priority);
      } else if (top.kind === 'faq') {
        lines.push('Q. ' + top.obj.q);
        lines.push('A. ' + top.obj.a);
      } else if (top.kind === 'routine') {
        lines.push(trunc(top.obj.text, 120));
        lines.push('· 주기: ' + top.obj.cadence + (top.obj.next ? ' · 다음 예정 ' + fmtD(top.obj.next) : ''));
      } else {
        lines.push(trunc(top.text, 160));
      }
      ev = [{ sec: top.sec, text: trunc(top.text, 110) }];
      if (found[1] && found[1].score > top.score * 0.6 && found[1].kind === top.kind) {
        ev.push({ sec: found[1].sec, text: trunc(found[1].text, 90) });
        lines.push('· 참고로 이것도 있습니다: ' + trunc(found[1].text, 70));
      }
    }
    return { text: lines.join('\n'), ev: ev };
  }

  function qaAsk(q) {
    var box = $('#qaLog');
    if (!q.trim()) return;
    box.insertAdjacentHTML('beforeend', '<div class="qa-msg me">' + esc(q) + '</div>');
    var a = answerQuestion(q);
    var evHtml = '';
    if (a && a.ev && a.ev.length) {
      evHtml = a.ev.map(function (e) {
        return '<span class="ev"><b>근거 · ' + esc(e.sec) + '</b><br>“' + esc(e.text) + '”</span>';
      }).join('');
    }
    box.insertAdjacentHTML('beforeend', '<div class="qa-msg bot">' + esc(a ? a.text : '인수인계서를 먼저 생성해 주세요.') + evHtml + '</div>');
    box.scrollTop = box.scrollHeight;
  }

  function renderQaChips() {
    var d = state.doc;
    var chips = [];
    var top = d.tasks.filter(function (t) { return t.dday !== null && t.dday >= 0; })[0];
    if (top) chips.push('오늘 가장 급한 일은?');
    chips.push('연락처 알려줘', '매월 해야 하는 일은?', '주의할 점은?');
    if (d.faq[0]) chips.push(trunc(d.faq[0].q, 22) + '?');
    $('#qaChips').innerHTML = chips.map(function (c) { return '<button type="button" data-q="' + esc(c) + '">' + esc(c) + '</button>'; }).join('');
  }

  /* ============================================================
     7. 내보내기
     ============================================================ */
  function docToMarkdown() {
    var d = state.doc, m = d.meta;
    var L = [];
    L.push('# ' + ((m.org || '업무') + ' 인수인계서'));
    L.push('');
    L.push('- 인계자: ' + (m.from || '-') + ' / 인수자: ' + (m.to || '-') + ' / 인계일: ' + (m.date || '-'));
    L.push('- 생성: ' + fmtD(d.generatedAt) + ' · 이어줌 AI (자료 ' + state.sources.length + '건)');
    L.push('');
    L.push('## ① 핵심 업무 요약');
    d.summary.forEach(function (s) { L.push('- ' + s); });
    L.push('');
    L.push('## ② 진행 중·미완료 과제');
    if (!d.tasks.length) L.push('- 없음');
    d.tasks.forEach(function (t) {
      L.push('- [' + t.priority + '] ' + t.text + (t.dday !== null ? ' (D-' + t.dday + ', 마감 ' + fmtD(t.due) + ')' : ''));
    });
    L.push('');
    L.push('## ③ 반복 루틴');
    if (!d.routines.length) L.push('- 없음');
    d.routines.forEach(function (r) { L.push('- (' + r.cadence + ') ' + r.text); });
    L.push('');
    L.push('## ④ 이해관계자·비상연락망');
    if (!d.contacts.length) L.push('- 없음');
    d.contacts.forEach(function (c) {
      var k = c.contact;
      L.push('- ' + (k.role || '') + ' ' + (k.name || '') + ' | ' + [k.phone, k.ext, k.email].filter(Boolean).join(' / ') + (k.note ? ' (' + k.note + ')' : ''));
    });
    L.push('');
    L.push('## ⑤ 트러블슈팅 FAQ');
    if (!d.faq.length) L.push('- 없음');
    d.faq.forEach(function (f) { L.push('- Q. ' + f.q); L.push('  A. ' + f.a); });
    L.push('');
    L.push('## ⑥ 인수자 첫 7일 온보딩');
    d.onboarding.forEach(function (day) {
      L.push('### DAY ' + day.n + ' · ' + day.title);
      day.items.forEach(function (it) { L.push('- [ ] ' + it.text); });
    });
    L.push('');
    L.push('## ⑦ 리스크·주의사항');
    if (!d.risks.length) L.push('- 없음');
    d.risks.forEach(function (r) { L.push('- (' + (r.level === 'high' ? '중대' : '주의') + ') ' + r.text); });
    L.push('');
    L.push('---');
    L.push('인계 완료도 ' + d.score.score + '점 · 누락 항목 ' + d.score.failCount + '개 · 이어줌 AI');
    return L.join('\n');
  }

  function docToHTML() {
    var d = state.doc, m = d.meta;
    var css = 'body{font-family:"Malgun Gothic","Apple SD Gothic Neo",sans-serif;font-size:10.5pt;color:#111;line-height:1.65}' +
      'h1{font-size:18pt;border-bottom:2px solid #1d4ed8;padding-bottom:6px;margin:0 0 10px}' +
      'h2{font-size:12pt;color:#1d4ed8;margin:16px 0 6px;border-left:4px solid #1d4ed8;padding-left:8px}' +
      'h3{font-size:10.5pt;margin:10px 0 4px;color:#333}' +
      'table{border-collapse:collapse;width:100%;margin:4px 0 8px}' +
      'td,th{border:1px solid #bbb;padding:5px 7px;font-size:9.5pt;vertical-align:top}' +
      'th{background:#eef3fb;text-align:left}' +
      '.meta{font-size:9.5pt;color:#444;margin-bottom:10px}' +
      'ul{margin:4px 0 8px 18px;padding:0}li{margin:2px 0}' +
      '.tag{color:#666;font-size:9pt}' +
      '.box{border:1px solid #bbb;background:#f7f9fc;padding:8px 10px;margin:6px 0}';
    var h = [];
    h.push('<h1>' + esc((m.org || '업무') + ' 인수인계서') + '</h1>');
    h.push('<p class="meta">인계자: ' + esc(m.from || '-') + ' &nbsp;|&nbsp; 인수자: ' + esc(m.to || '-') + ' &nbsp;|&nbsp; 인계일: ' + esc(m.date || '-') + '<br>생성일: ' + fmtD(d.generatedAt) + ' · 이어줌 AI 업무 인수인계 · 인계 완료도 ' + d.score.score + '점</p>');

    h.push('<h2>① 핵심 업무 요약</h2><ul>' + d.summary.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ul>');

    h.push('<h2>② 진행 중·미완료 과제</h2>');
    if (d.tasks.length) {
      h.push('<table><tr><th style="width:8%">우선</th><th>과제</th><th style="width:16%">마감</th></tr>' +
        d.tasks.map(function (t) {
          return '<tr><td>' + t.priority + '</td><td>' + esc(t.text) + '</td><td>' +
            (t.dday !== null ? 'D-' + t.dday + '<br>' + fmtD(t.due) : '미지정') + '</td></tr>';
        }).join('') + '</table>');
    } else h.push('<p>없음</p>');

    h.push('<h2>③ 반복 루틴</h2>');
    if (d.routines.length) {
      h.push('<table><tr><th style="width:18%">주기</th><th>업무</th><th style="width:16%">다음 예정</th></tr>' +
        d.routines.map(function (r) {
          return '<tr><td>' + esc(r.cadence) + '</td><td>' + esc(r.text) + '</td><td>' + (r.next ? fmtD(r.next) : '-') + '</td></tr>';
        }).join('') + '</table>');
    } else h.push('<p>없음</p>');

    h.push('<h2>④ 이해관계자·비상연락망</h2>');
    if (d.contacts.length) {
      h.push('<table><tr><th>구분</th><th>이름</th><th>연락처</th><th>참고</th></tr>' +
        d.contacts.map(function (c) {
          var k = c.contact;
          return '<tr><td>' + esc(k.role || '') + '</td><td>' + esc(k.name || '') + '</td><td>' +
            esc([k.phone, k.ext, k.email].filter(Boolean).join(' / ')) + '</td><td>' + esc(k.note || '') + '</td></tr>';
        }).join('') + '</table>');
    } else h.push('<p>없음</p>');

    h.push('<h2>⑤ 트러블슈팅 FAQ</h2>');
    if (d.faq.length) {
      h.push(d.faq.map(function (f, i) {
        return '<p><b>Q' + (i + 1) + '. ' + esc(f.q) + '</b><br>A. ' + esc(f.a) + '</p>';
      }).join(''));
    } else h.push('<p>없음</p>');

    h.push('<h2>⑥ 인수자 첫 7일 온보딩</h2>');
    d.onboarding.forEach(function (day) {
      h.push('<h3>DAY ' + day.n + ' · ' + esc(day.title) + '</h3><ul>' +
        day.items.map(function (it) { return '<li>☐ ' + esc(it.text) + '</li>'; }).join('') + '</ul>');
    });

    h.push('<h2>⑦ 리스크·주의사항</h2>');
    if (d.risks.length) {
      h.push('<ul>' + d.risks.map(function (r) {
        return '<li><b>[' + (r.level === 'high' ? '중대' : '주의') + ']</b> ' + esc(r.text) + '</li>';
      }).join('') + '</ul>');
    } else h.push('<p>없음</p>');

    h.push('<hr><p class="tag">이 문서는 이어줌 AI가 자동 생성했습니다. 개인정보는 ' + (state.maskOn ? '마스킹된 상태입니다.' : '포함되어 있을 수 있으니 배포 전 확인하세요.') + '</p>');

    return '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40"><head><meta charset="utf-8">' +
      '<title>' + esc((m.org || '업무') + ' 인수인계서') + '</title><style>' + css + '</style></head><body>' + h.join('') + '</body></html>';
  }

  function download(filename, content, mime) {
    var blob = new Blob(['\ufeff' + content], { type: mime || 'text/plain;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  function safeName() {
    var base = (state.meta.org || '업무') + '_인수인계서_' + dateInput(new Date()).replace(/-/g, '');
    return base.replace(/[\\/:*?"<>|]/g, '');
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast('Markdown을 복사했습니다.'); })
        .catch(function () { fallbackCopy(text); });
    } else fallbackCopy(text);
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); toast('Markdown을 복사했습니다.'); } catch (e) { toast('복사에 실패했습니다. 직접 선택해 주세요.', true); }
    ta.remove();
  }

  /* ============================================================
     8. AI 정밀 분석 (선택)
     ============================================================ */
  function aiKey() {
    var p = lsGet('ai.provider', 'openai');
    return { provider: p, key: lsGet('ai.key.' + p, '') };
  }

  function buildPrompt(text) {
    return '너는 공공기관 업무 인수인계 전문가다. 아래 자료를 분석해 인수인계서를 JSON으로만 출력해라.\n' +
      '규칙: 1) 자료에 없는 내용은 만들지 말 것 2) 개인정보는 그대로 두지 말고 가린 형태 유지 3) 한국어로 간결하게\n' +
      'JSON 스키마:\n' +
      '{"summary":["핵심 업무 3~5문장"],' +
      '"tasks":[{"text":"과제","due":"YYYY-MM-DD 또는 null","priority":"상|중|하"}],' +
      '"routines":[{"text":"반복업무","cadence":"매월 5일"}],' +
      '"contacts":[{"name":"","role":"","phone":"","email":"","note":""}],' +
      '"faq":[{"q":"질문","a":"답변"}],' +
      '"onboarding":[["DAY1 항목1","항목2"],["DAY2 ..."],["DAY3 ..."],["DAY4 ..."],["DAY5 ..."],["DAY6 ..."],["DAY7 ..."]],' +
      '"risks":[{"text":"주의사항","level":"high|mid"}]}\n\n[자료]\n' + text;
  }

  function extractJSON(s) {
    if (!s) return null;
    var t = String(s).trim().replace(/^```(?:json)?/i, '').replace(/```$/, '').trim();
    var i = t.indexOf('{'), j = t.lastIndexOf('}');
    if (i >= 0 && j > i) t = t.slice(i, j + 1);
    try { return JSON.parse(t); } catch (e) { return null; }
  }

  async function callOpenAI(key, prompt) {
    var res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        temperature: 0.2,
        response_format: { type: 'json_object' },
        messages: [{ role: 'user', content: prompt }]
      })
    });
    if (!res.ok) {
      var txt = await res.text();
      throw new Error('OpenAI ' + res.status + ' ' + txt.slice(0, 160));
    }
    var j = await res.json();
    return j.choices && j.choices[0] && j.choices[0].message.content;
  }

  async function callGemini(key, prompt) {
    var url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' + encodeURIComponent(key);
    var res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2, responseMimeType: 'application/json' }
      })
    });
    if (!res.ok) {
      var txt = await res.text();
      throw new Error('Gemini ' + res.status + ' ' + txt.slice(0, 160));
    }
    var j = await res.json();
    return j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts
      ? j.candidates[0].content.parts.map(function (p) { return p.text || ''; }).join('') : '';
  }

  async function runAI() {
    if (!state.sources.length) { toast('먼저 자료를 넣어 주세요.', true); return; }
    var ak = aiKey();
    if (!ak.key) { openAiModal(); toast('API 키를 등록하면 AI 정밀 분석을 쓸 수 있습니다.'); return; }

    var btn = $('#btnAiRun');
    btn.disabled = true;
    var old = btn.textContent;
    btn.textContent = '분석 중…';
    try {
      var text = state.sources.map(function (s) { return '### ' + s.name + '\n' + processedText(s); }).join('\n\n');
      if (text.length > 60000) text = text.slice(0, 60000);
      var raw = ak.provider === 'openai' ? await callOpenAI(ak.key, buildPrompt(text)) : await callGemini(ak.key, buildPrompt(text));
      var j = extractJSON(raw);
      if (!j) throw new Error('응답을 JSON으로 해석하지 못했습니다.');
      applyAI(j, ak.provider === 'openai' ? 'OpenAI' : 'Gemini');
      toast('AI 정밀 분석 결과로 인수인계서를 갱신했습니다.');
    } catch (e) {
      console.warn(e);
      toast('AI 분석 실패(' + (e.message || e) + ') — 내장 엔진 결과를 그대로 사용합니다.', true);
    } finally {
      btn.disabled = false;
      btn.textContent = old;
    }
  }

  function applyAI(j, who) {
    var d = state.doc;
    if (!d) return;
    if (Array.isArray(j.summary) && j.summary.length) {
      d.summary = j.summary.map(String).slice(0, 6);
    }
    if (Array.isArray(j.tasks) && j.tasks.length) {
      d.tasks = j.tasks.map(function (t) {
        var text = String(t.text || t).trim();
        var due = null;
        if (t.due && /^\d{4}-\d{2}-\d{2}/.test(t.due)) {
          var p = t.due.split('-');
          due = mkDate(+p[0], +p[1], +p[2]);
        }
        var dd = ddayOf(due);
        return { id: uid('a'), type: 'task', text: text, source: 'AI', due: due, dday: dd, priority: t.priority || priorityOf(text, dd), cadence: '' };
      });
    }
    if (Array.isArray(j.routines) && j.routines.length) {
      d.routines = j.routines.map(function (r) {
        var text = String(r.text || r).trim();
        var c = routineCadence(r.cadence ? text + ' ' + r.cadence : text);
        return { id: uid('a'), type: 'routine', text: text, source: 'AI', cadence: r.cadence || c.label, cadenceKey: c.key, next: c.next, dom: c.dom, priority: '하', dday: null, due: null };
      });
    }
    if (Array.isArray(j.contacts) && j.contacts.length) {
      d.contacts = j.contacts.map(function (c) {
        return {
          id: uid('a'), type: 'contact', source: 'AI',
          text: [c.role, c.name, c.phone, c.email, c.note].filter(Boolean).join(' '),
          contact: { name: c.name || '', role: c.role || '', phone: c.phone || '', ext: '', email: c.email || '', note: c.note || '' }
        };
      });
    }
    if (Array.isArray(j.faq) && j.faq.length) {
      d.faq = j.faq.map(function (f) {
        return { id: uid('a'), type: 'faq', source: 'AI', q: String(f.q || ''), a: String(f.a || ''), text: (f.q || '') + ' → ' + (f.a || '') };
      });
    }
    if (Array.isArray(j.risks) && j.risks.length) {
      d.risks = j.risks.map(function (r) {
        var text = typeof r === 'string' ? r : String(r.text || '');
        var level = (r && r.level === 'high') ? 'high' : (/개인정보|금지|법|감사|청탁/.test(text) ? 'high' : 'mid');
        return { id: uid('a'), type: 'risk', source: 'AI', text: text, level: level };
      });
    }
    if (Array.isArray(j.onboarding) && j.onboarding.length) {
      d.onboarding = j.onboarding.slice(0, 7).map(function (items, i) {
        var arr = Array.isArray(items) ? items : [String(items)];
        return {
          n: i + 1,
          title: (d.onboarding[i] && d.onboarding[i].title) || ('DAY ' + (i + 1)),
          items: arr.filter(Boolean).map(function (t, k) {
            return { key: 'a' + i + '-' + k, text: String(t), done: false };
          })
        };
      });
    }
    // AI 결과로 항목·통계·점수를 다시 구성한다
    var aiItems = [];
    d.summary.forEach(function (t, i) { aiItems.push({ id: 'ai-s' + i, type: 'info', text: t, source: 'AI', heading: '업무 개요' }); });
    d.tasks.forEach(function (t) { aiItems.push(t); });
    d.routines.forEach(function (t) { aiItems.push(t); });
    d.contacts.forEach(function (t) { aiItems.push(t); });
    d.faq.forEach(function (t) { aiItems.push(t); });
    d.risks.forEach(function (t) { aiItems.push(t); });
    d.items = aiItems;
    d.infos = d.summary.map(function (t, i) { return { id: 'ai-i' + i, type: 'info', text: t, source: 'AI', heading: '업무 개요' }; });
    d.stats.tasks = d.tasks.length;
    d.stats.urgent = d.tasks.filter(function (t) { return t.dday !== null && t.dday <= 7; }).length;
    d.stats.routines = d.routines.length;
    d.stats.contacts = d.contacts.length;
    d.stats.faq = d.faq.length;
    d.stats.risks = d.risks.length;
    d.score = scoreDoc(d);
    state.aiUsedBy = who;
    renderDoc();
  }

  function openAiModal() {
    var ak = aiKey();
    $('#aiProvider').value = ak.provider;
    $('#aiKey').value = ak.key || '';
    $('#aiModal').hidden = false;
    setTimeout(function () { $('#aiKey').focus(); }, 50);
  }

  /* ============================================================
     9. 자료 조작
     ============================================================ */
  function addSource(name, kind, raw) {
    var scan = scanPII(raw, state.maskLevel);
    state.sources.push({
      id: uid('s'), name: name, kind: kind, raw: raw,
      masked: scan.masked, findings: scan.findings
    });
    renderSources();
    renderMask();
    saveWork();
  }

  function reScan() {
    state.sources.forEach(function (s) {
      var sc = scanPII(s.raw, state.maskLevel);
      s.masked = sc.masked;
      s.findings = sc.findings;
    });
    renderSources();
    renderMask();
  }

  function readFile(file) {
    return new Promise(function (resolve) {
      var fr = new FileReader();
      fr.onload = function () {
        var buf = fr.result;
        var text = '';
        try { text = new TextDecoder('utf-8').decode(buf); } catch (e) { text = ''; }
        var bad = (text.match(/\uFFFD/g) || []).length;
        if (!text || bad > Math.max(2, text.length * 0.01)) {
          try { text = new TextDecoder('euc-kr').decode(buf); } catch (e2) { /* 무시 */ }
        }
        resolve(text || '');
      };
      fr.onerror = function () { resolve(''); };
      fr.readAsArrayBuffer(file);
    });
  }

  function handleFiles(files) {
    var arr = Array.prototype.slice.call(files || []);
    if (!arr.length) return;
    var jobs = arr.map(function (f) {
      if (f.size > 3 * 1024 * 1024) { toast(f.name + ' — 3MB를 넘어 건너뜁니다.', true); return null; }
      return readFile(f).then(function (text) {
        if (!text.trim()) { toast(f.name + ' — 내용을 읽지 못했습니다.', true); return; }
        if (/\.csv$/i.test(f.name)) text = splitCSV(text);
        addSource(f.name, 'file', text);
      });
    }).filter(Boolean);
    Promise.all(jobs).then(function () {
      if (!jobs.length) return;
      generate();
      toast(jobs.length + '개 파일을 분석해 인수인계서를 만들었습니다.');
    });
  }

  function saveWork() {
    lsSet('work', {
      sources: state.sources.map(function (s) { return { name: s.name, kind: s.kind, raw: s.raw }; }),
      meta: state.meta, maskOn: state.maskOn, maskLevel: state.maskLevel
    });
  }

  function restoreWork() {
    var w = lsGet('work', null);
    if (w && Array.isArray(w.sources)) {
      w.sources.forEach(function (s) {
        var sc = scanPII(s.raw, (w.maskLevel || 'partial'));
        state.sources.push({ id: uid('s'), name: s.name, kind: s.kind || 'paste', raw: s.raw, masked: sc.masked, findings: sc.findings });
      });
      state.meta = w.meta || state.meta;
      state.maskOn = w.maskOn !== false;
      state.maskLevel = w.maskLevel || 'partial';
    }
  }

  /* ============================================================
     10. 이벤트 연결
     ============================================================ */
  function syncMetaInputs() {
    $('#metaOrg').value = state.meta.org || '';
    $('#metaFrom').value = state.meta.from || '';
    $('#metaTo').value = state.meta.to || '';
    if (!state.meta.date) { state.meta.date = dateInput(new Date()); state.meta.dateAuto = true; }
    $('#metaDate').value = state.meta.date || dateInput(new Date());
  }

  function initEvents() {
    $('#metaOrg').addEventListener('input', function () { state.meta.org = this.value; saveWork(); });
    $('#metaFrom').addEventListener('input', function () { state.meta.from = this.value; saveWork(); });
    $('#metaTo').addEventListener('input', function () { state.meta.to = this.value; saveWork(); });
    $('#metaDate').addEventListener('change', function () { state.meta.date = this.value; state.meta.dateAuto = false; saveWork(); });

    document.addEventListener('click', function (ev) {
      var sb = ev.target.closest('[data-sample]');
      if (sb) {
        var id = sb.getAttribute('data-sample');
        var samp = (window.IEOJUM_SAMPLES || []).filter(function (s) { return s.id === id; })[0];
        if (!samp) return;
        // 같은 샘플이 이미 있으면 중복 투입하지 않는다
        if (state.sources.some(function (s) { return s.name === samp.name; })) {
          toast('이미 추가된 샘플입니다.');
        } else {
          addSource(samp.name, 'sample', samp.text);
          if (!state.meta.org) {
            state.meta.org = id === 'hospital' ? '새솔시립병원 시설안전팀' : '미래구청 민원실';
            $('#metaOrg').value = state.meta.org;
          }
          saveWork();
          toast('샘플 자료를 추가했습니다. ‘인수인계서 생성’을 눌러 보세요.');
        }
        generate();
        return;
      }
      var rm = ev.target.closest('[data-rm]');
      if (rm) {
        var rid = rm.getAttribute('data-rm');
        state.sources = state.sources.filter(function (s) { return s.id !== rid; });
        renderSources(); renderMask(); saveWork();
        if (state.sources.length) generate(); else resetDoc();
        return;
      }
      var onb = ev.target.closest('input[data-onb]');
      if (onb) {
        var h = onb.getAttribute('data-onb');
        lsSet('onb.' + h, onb.checked);
        var li = onb.closest('li');
        if (li) li.classList.toggle('done', onb.checked);
        return;
      }
      var chip = ev.target.closest('[data-q]');
      if (chip) { openQa(); qaAsk(chip.getAttribute('data-q')); return; }
    });

    // 파일
    var dz = $('#dropzone');
    dz.addEventListener('click', function () { $('#fileInput').click(); });
    dz.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('#fileInput').click(); } });
    $('#fileInput').addEventListener('change', function () { handleFiles(this.files); this.value = ''; });
    ['dragenter', 'dragover'].forEach(function (t) {
      dz.addEventListener(t, function (e) { e.preventDefault(); dz.classList.add('drag'); });
    });
    ['dragleave', 'drop'].forEach(function (t) {
      dz.addEventListener(t, function (e) { e.preventDefault(); dz.classList.remove('drag'); });
    });
    dz.addEventListener('drop', function (e) { handleFiles(e.dataTransfer.files); });
    document.addEventListener('dragover', function (e) { e.preventDefault(); });
    document.addEventListener('drop', function (e) { e.preventDefault(); });

    // 붙여넣기 추가
    $('#btnAddPaste').addEventListener('click', function () {
      var v = $('#pasteInput').value.trim();
      if (v.length < 10) { toast('자료가 너무 짧습니다. 10자 이상 붙여넣어 주세요.', true); return; }
      addSource('붙여넣은 자료 ' + (state.sources.filter(function (s) { return s.kind === 'paste'; }).length + 1), 'paste', v);
      $('#pasteInput').value = '';
      toast('자료를 추가했습니다.');
      generate();
    });
    $('#pasteInput').addEventListener('input', function () {
      var n = this.value.length;
      $('#pasteCount').textContent = n ? n.toLocaleString() + '자' : '';
    });
    $('#btnClearSources').addEventListener('click', function () {
      if (!state.sources.length) return;
      state.sources = []; renderSources(); renderMask(); saveWork(); resetDoc();
      toast('자료를 모두 비웠습니다.');
    });

    // 마스킹
    $('#maskToggle').addEventListener('change', function () {
      state.maskOn = this.checked;
      reScan();
      saveWork();
      if (state.doc) generate();
      toast(state.maskOn ? '마스킹을 켰습니다. 화면·AI 전송 모두 가려진 상태로 처리됩니다.' : '마스킹을 껐습니다. 개인정보가 문서에 그대로 표시됩니다.', !state.maskOn);
    });
    $('#maskLevel').addEventListener('change', function () {
      state.maskLevel = this.value;
      reScan(); saveWork();
      if (state.doc) generate();
    });

    // 생성
    $('#btnGenerate').addEventListener('click', function () { generate(true); });
    $('#btnAiRun').addEventListener('click', runAI);

    // 초기화
    $('#btnReset').addEventListener('click', function () {
      if (!confirm('작성 중인 자료와 인수인계서를 모두 지우고 처음부터 시작할까요?')) return;
      state.sources = []; state.doc = null; state.aiUsedBy = '';
      state.meta = { org: '', from: '', to: '', date: dateInput(new Date()) };
      try { localStorage.removeItem(LS_PREFIX + 'work'); } catch (e) {}
      syncMetaInputs(); renderSources(); renderMask(); resetDoc();
      toast('새로 시작합니다.');
    });

    // 내보내기
    $('#btnPrint').addEventListener('click', function () {
      if (!state.doc) return;
      window.print();
    });
    $('#btnWord').addEventListener('click', function () {
      if (!state.doc) return;
      download(safeName() + '.doc', docToHTML(), 'application/msword');
      toast('Word(.doc) 파일을 내려받았습니다.');
    });
    $('#btnMd').addEventListener('click', function () {
      if (!state.doc) return;
      copyText(docToMarkdown());
    });
    $('#btnJson').addEventListener('click', function () {
      if (!state.doc) return;
      var d = state.doc;
      var out = {
        meta: d.meta, generatedAt: d.generatedAt,
        score: d.score.score, checks: d.score.checks,
        summary: d.summary,
        tasks: d.tasks.map(function (t) { return { text: t.text, due: t.due ? dateInput(t.due) : null, dday: t.dday, priority: t.priority }; }),
        routines: d.routines.map(function (r) { return { text: r.text, cadence: r.cadence }; }),
        contacts: d.contacts.map(function (c) { return c.contact; }),
        faq: d.faq.map(function (f) { return { q: f.q, a: f.a }; }),
        onboarding: d.onboarding,
        risks: d.risks.map(function (r) { return { text: r.text, level: r.level }; }),
        piiMasked: state.maskOn
      };
      download(safeName() + '.json', JSON.stringify(out, null, 2), 'application/json');
      toast('JSON 파일을 내려받았습니다.');
    });

    // Q&A
    $('#qaFab').addEventListener('click', function () { openQa(); });
    $('#btnQa').addEventListener('click', function () { openQa(); });
    $('#qaClose').addEventListener('click', closeQa);
    $('#qaForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var v = $('#qaText').value;
      $('#qaText').value = '';
      qaAsk(v);
    });

    // AI 설정
    $('#btnAiSettings').addEventListener('click', openAiModal);
    $('#aiCancel').addEventListener('click', function () { $('#aiModal').hidden = true; });
    $('#aiSave').addEventListener('click', function () {
      var p = $('#aiProvider').value, k = $('#aiKey').value.trim();
      lsSet('ai.provider', p);
      lsSet('ai.key.' + p, k);
      $('#aiModal').hidden = true;
      toast(k ? 'API 키를 이 브라우저에만 저장했습니다.' : '키를 비웠습니다.');
      $('#engineHint').textContent = k ? 'AI 정밀 분석 사용 가능 · 내장 엔진도 그대로 동작' : 'API 키 없이도 내장 엔진으로 100% 동작합니다.';
    });
    $('#aiDelete').addEventListener('click', function () {
      var p = $('#aiProvider').value;
      lsSet('ai.key.' + p, '');
      $('#aiKey').value = '';
      toast('저장된 키를 삭제했습니다.');
    });
    $('#aiModal').addEventListener('click', function (e) { if (e.target === this) this.hidden = true; });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        $('#aiModal').hidden = true;
        if (!$('#qaPanel').hidden) closeQa();
      }
    });
  }

  function openQa() {
    if (!state.doc) { toast('먼저 인수인계서를 생성해 주세요.', true); return; }
    $('#qaPanel').hidden = false;
    $('#qaFab').setAttribute('aria-expanded', 'true');
    if (!$('#qaLog').children.length) {
      $('#qaLog').insertAdjacentHTML('beforeend', '<div class="qa-msg bot">안녕하세요, 후임자입니다. 인수인계서를 읽고 궁금한 점을 물어보겠습니다.\n아래 예시를 누르거나 직접 입력해 주세요.<span class="ev"><b>답변 방식</b><br>인수인계서 문단을 근거로 함께 보여 드립니다.</span></div>');
    }
    setTimeout(function () { $('#qaText').focus(); }, 60);
  }
  function closeQa() {
    $('#qaPanel').hidden = true;
    $('#qaFab').setAttribute('aria-expanded', 'false');
  }

  function resetDoc() {
    state.doc = null;
    $('#emptyState').hidden = false;
    $('#docRoot').hidden = true;
    $('#docRoot').innerHTML = '';
    $('#docToolbar').hidden = true;
    $('#scoreCard').hidden = true;
    $('#qaFab').hidden = true;
    closeQa();
  }

  function generate(showToast) {
    if (!state.sources.length) {
      toast('먼저 자료를 넣어 주세요. 샘플 버튼으로 바로 체험할 수 있습니다.', true);
      return;
    }
    state.aiUsedBy = '';
    state.doc = buildDoc();
    state.lastGenerated = new Date();
    syncMetaInputs();
    renderDoc();
    saveWork();
    if (showToast) toast('인수인계서를 생성했습니다. 점수 ' + state.doc.score.score + '점');
    if (showToast && window.innerWidth <= 920) {
      var el = document.getElementById('docRoot');
      if (el) setTimeout(function () { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 60);
    }
  }

  /* ============================================================
     11. 시작
     ============================================================ */
  function init() {
    restoreWork();
    syncMetaInputs();
    renderSources();
    renderMask();
    initEvents();
    $('#maskToggle').checked = state.maskOn;
    $('#maskLevel').value = state.maskLevel;

    var ak = aiKey();
    if (ak.key) $('#engineHint').textContent = 'AI 정밀 분석 사용 가능 · 내장 엔진도 그대로 동작';

    if (state.sources.length) generate();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
