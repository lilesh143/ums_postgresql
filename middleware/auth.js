const isAuthorize = async(req, res, next) => {
    try {

        if (!req.headers.authorization ||
            !req.headers.authorization.startsWith('bearer') ||
            !req.headers.authorization.split(' ')[1]
        ) {
            res.status(422).json({
                msg: 'Please provide token'
            })
        }

    } catch (error) {
        console.log(error.message);

    }

    next()
}

module.exports = {
    isAuthorize
}