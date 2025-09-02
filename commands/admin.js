async function clearchatmsgs(chatid, msgid, bot) {
    try {
        for (let i = msgid; i > msgid - 100; i--) {
            try {
                await bot.deleteMessage(chatid, i);
            } catch (e) {
            
            }
        }
        return true;
    } catch (e) {
        console.error('Error clearing chat:', e.message);
        return false;
    }
}

async function clearchat(chatid, msgid, bot, sendmsg) {
    const cleared = await clearchatmsgs(chatid, msgid, bot);
    if (cleared) {
        await sendmsg(chatid, 'chat cleared');
    } else {
        await sendmsg(chatid, 'chat clear error');
    }
}

async function antispamtoggle(chatid, antispamstatus, sendmsg) {

    await sendmsg(chatid, `antispam ${antispamstatus ? 'on' : 'off'}`);
}

async function banuser(chatid, args, bannedusers, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'user id required');
    const id = parseInt(args[1]);
    if (isNaN(id)) {
        await sendmsg(chatid, 'invalid user id');
        return;
    }
    bannedusers.add(id);
    await sendmsg(chatid, `user ${id} banned`);
}

async function unbanuser(chatid, args, bannedusers, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'user id required');
    const id = parseInt(args[1]);
    if (isNaN(id)) {
        await sendmsg(chatid, 'invalid user id');
        return;
    }
    bannedusers.delete(id);
    await sendmsg(chatid, `user ${id} unbanned`);
}

module.exports = {
    clearchat,
    antispamtoggle,
    banuser,
    unbanuser
};