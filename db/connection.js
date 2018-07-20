const monk = require('monk')

const db = monk('localhost/capstoneDb')

module.exports = db