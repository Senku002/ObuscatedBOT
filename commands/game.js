function pickq(quizq, usedq) {
    if (usedq.length === quizq.length) usedq.length = 0;
    const rem = quizq.filter(q => !usedq.includes(q));
    if (rem.length === 0) return null;
    const idx = Math.floor(Math.random() * rem.length);
    const q = rem[idx];
    usedq.push(q);
    return q;
}

async function startquiz(id, quizactiveStatus, currentqStatus, quizqList, usedqList, answertimeStatus, sendmsgFunc, setCurrentQ, setAnswerTime, setQuizActive) {
    if (!quizactiveStatus) return;
    const newQ = pickq(quizqList, usedqList);
    setCurrentQ(newQ);
    if (!newQ) {
        await sendmsgFunc(id, 'no more questions');
        setQuizActive(false);
        return;
    }
    setAnswerTime(Date.now());
    await sendmsgFunc(id, `new question: ${newQ.q}\n60s to answer`);
    setTimeout(() => chkquiz(id, currentqStatus, quizactiveStatus, sendmsgFunc, setCurrentQ, setQuizActive, quizqList, usedqList, answertimeStatus), 60000);
}

function chkquiz(id, currentqStatus, quizactiveStatus, sendmsgFunc, setCurrentQ, setQuizActive, quizqList, usedqList, answertimeStatus) {
    if (!currentqStatus || !quizactiveStatus) return;
    setCurrentQ(null);
    sendmsgFunc(id, 'time up. wait for next question');
    setTimeout(() => startquiz(id, quizactiveStatus, currentqStatus, quizqList, usedqList, answertimeStatus, sendmsgFunc, setCurrentQ, setQuizActive), 600000);
}

function updategrp(user, pts, groupsMap) {
    let currentgrp = 'incepator';
    if (groupsMap.avansat.has(user)) currentgrp = 'avansat';
    else if (groupsMap.coder.has(user)) currentgrp = 'coder';
    else if (groupsMap.hacker.has(user)) currentgrp = 'hacker';

    groupsMap[currentgrp].set(user, pts);
    if (currentgrp === 'incepator' && pts >= 10) {
        groupsMap.incepator.delete(user);
        groupsMap.avansat.set(user, 0);
        return { newgrp: 'avansat', medal: 'bronze medal' };
    } else if (currentgrp === 'avansat' && pts >= 15) {
        groupsMap.avansat.delete(user);
        groupsMap.coder.set(user, 0);
        return { newgrp: 'coder', medal: 'silver medal' };
    } else if (currentgrp === 'coder' && pts >= 20) {
        groupsMap.coder.delete(user);
        groupsMap.hacker.set(user, 0);
        return { newgrp: 'hacker', medal: 'gold medal' };
    } else if (currentgrp === 'hacker' && pts >= 40) {
        return { newgrp: 'hacker', medal: 'hacker legend' };
    }
    return { newgrp: currentgrp, medal: null };
}

async function startgame(chatid, quizqList, sendmsgFunc, setQuizActive, setCurrentQ, usedqList, answertimeStatus) {
    if (quizqList.length === 0) {
        await sendmsgFunc(chatid, 'no questions');
        return;
    }
    setQuizActive(true);
    await sendmsgFunc(chatid, 'quiz started. first question soon');
    setTimeout(() => startquiz(chatid, true, null, quizqList, usedqList, answertimeStatus, sendmsgFunc, setCurrentQ, (t) => {}, (a) => { setQuizActive(a); }), 10000);
}

async function stopgame(chatid, sendmsgFunc, setQuizActive, setCurrentQ) {
    setQuizActive(false);
    setCurrentQ(null);
    await sendmsgFunc(chatid, 'quiz stopped');
}

module.exports = {
    pickq,
    startquiz,
    chkquiz,
    updategrp,
    startgame,
    stopgame
};