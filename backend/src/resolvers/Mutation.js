const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require("../mail");
const { hasPermission } = require('../utils');

const Mutations = {
    async createItem(parent, args, ctx, info) {
        if(!ctx.request.userId) {
            throw new Error("You must be logged in to do that");
        }

        const item = await ctx.db.mutation.createItem({
            data: {
                // This is how we create relation between the Item and the User
                user: {
                    connect: {
                        id: ctx.request.userId
                    }
                },
                ...args
            }
        }, info);

        return item;
    },

    updateItem(parent, args, ctx, info) {
        // First take a scope of the updates
        const updates = { ... args};
        // Remove the ID from the updates
        delete updates.id;
        // Run the update method
        return ctx.db.mutation.updateItem({
            data: updates,
            where: {
                id: args.id
            }
        }, info);
    },

    async deleteItem(parent, args, ctx, info) {
        const where = { id: args.id };
        // Find the item
        const item = await ctx.db.query.item({ where }, `{ id title user { id } }`);
        // Check if they own that item or have permission
        const ownsItem = item.user.id === ctx.request.userId;
        const hasPermissions = ctx.request.user.permissions.some
        (permission => 
            ['ADMIN', 'ITEMDELETE'].includes(permission)
        );

        if (!ownsItem && !hasPermission) {
            throw new Error("You don't have permission to do that!");
        }
        // Delete it
        return ctx.db.mutation.deleteItem({ where }, info);
    },

    async signup(parent, args, ctx, info) {
        // lowercase the email
        args.email = args.email.toLowerCase();
        // hash the password
        const password = await bcrypt.hash(args.password, 10);
        // Create the user in the database
        const user = await ctx.db.mutation.createUser({
            data: {
                ...args,
                password,
                permissions: { set: ['USER'] }
            }
        }, info);

        // Create JWT token
        const token = jwt.sign({
            userId: user.id
        }, process.env.APP_SECRET);
        // Set the jwt as a cookie on the response
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
        });

        return user;
    },

    async signin(parent, {email, password}, ctx, info) {
        // check if there user with that email
        const user = await ctx.db.query.user({ where: { email: email }});
        if(!user) {
            throw new Error(`No such user found for ${email}`);
        }
        // check if password is correct
        const valid = await bcrypt.compare(password, user.password);
        if(!valid) {
            throw new Error('Invalid password');
        }

        // generate jwt token
        const token = jwt.sign({
            userId: user.id
        }, process.env.APP_SECRET);

        // set cookie with the token
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
        });

        // return user
        return user;
    },

    signout(parent, args, ctx, info) {
        ctx.response.clearCookie('token');

        return { 
            message: 'Goodbye!'
        }
    },

    async requestReset(parent, args, ctx, info) {
        // Check if this is a real user
        const user = await ctx.db.query.user({ where: { email: args.email }});
        if (!user) {
            throw new Error(`No such user found for ${args.email}`);
        }

        // Set a reset token and expiry on that user
        const resetToken = (await promisify(randomBytes)(20)).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
        const res = await ctx.db.mutation.updateUser({
            where: { email: args.email },
            data: { resetToken, resetTokenExpiry }
        });

        // Email them the reset token.
        const mailRes = await transport.sendMail({
            from: 'harsh@harsh.com',
            to: user.email,
            subject: 'Your Password Reset Token',
            html: makeANiceEmail(`Your Password Reset Token is here! 
            \n\n 
            <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click Here to Reset</a>`)
        });

        return { message: 'Thanks!' }
    },

    async resetPassword(parents, args, ctx, info) {
        // Check if passwords match
        if(args.password !== args.confirmPassword) {
            throw new Error('Your passwords dont match');
        }

        // Check if legit reset token and Check if its expired
        const [user] = await ctx.db.query.users({
            where: {
                resetToken: args.resetToken,
                resetTokenExpiry_gte: Date.now() - 3600000
            }
        });
        if(!user) {
            throw new Error('This token is either invalid or expired');
        }
        // Hash new password
        const password = await bcrypt.hash(args.password, 10);
        // Save the new password to the user and Remove old reset token fields
        const updatedUser = await ctx.db.mutation.updateUser({
            where: { email: user.email },
            data: {
                password,
                resetToken: null,
                resetTokenExpiry: null
            }
        });

        // Generate jwt
        const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
        // Set jwt cookie
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365
        });
        // Return new user
        return updatedUser;
    },

    async updatePermissions(parent, args, ctx, info) {
        // check if logged in
        if(!ctx.request.userId) {
            throw new Error('You must be logged in to do that!');
        }
        // query the current user
        const currentUser = await ctx.db.query.user({
            where: {
                id: ctx.request.userId
            }
        }, info);
        // check if they have the permission to do this
        hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
        // update permissions
        return ctx.db.mutation.updateUser({
            data: {
                permissions: {
                    set: args.permissions
                }
            },
            where: {
                id: args.userId
            }
        }, info);
    },

    async addToCart(parent, args, ctx, info) {

        // Are you signed in?
        const userId = ctx.request.userId;
        if(!userId) {
            throw new Error('You mused be signed in.');
        };
        // Query the users current cart
        const [existingCartItem] = await ctx.db.query.cartItems({
            where: {
                user: { id: userId },
                item: { id: args.id }
            }
        });

        // Check if that item is already in that cart, increment by 1 if it is
        if(existingCartItem) {
            return ctx.db.mutation.updateCartItem({
                where: { id: existingCartItem.id },
                data: { quantity: existingCartItem.quantity + 1}
            }, info);
        }
        // If it's not in the cart, create a fresh CartItem for that user
        return ctx.db.mutation.createCartItem({
            data: {
                user: {
                    connect: { id: userId }
                },
                item: {
                    connect: { id: args.id}
                }
            }
        }, info);
    }
};

module.exports = Mutations;
