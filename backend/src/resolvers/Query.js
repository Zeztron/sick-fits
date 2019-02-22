const Query = {
    dogs(parent, args, ctx, info) {
        global.dogs = gloal.dogs || [];
        return global.dogs;
    }
};

module.exports = Query;
