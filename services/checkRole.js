require('dotenv').config();

function checkRole(request, response, next) {
    if (response.locals.role == process.env.USER) {
        response.sendStatus(401);
    } else {
        next();
    }
}

module.exports = { checkRole: checkRole };
