'use strict';

const rsa = require('rsa');
const bc = require('bigint-conversion');

let keyPair;

async function getPublicKey(req, res) {
  try {
    keyPair = await rsa.generateRandomKeys();
    res.status(200).send({
      e: bc.bigintToHex(keyPair["publicKey"]["e"]),
      n: bc.bigintToHex(keyPair["publicKey"]["n"])
    })
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}

async function postMsg(req, res) {
  try {
    const c = req.body.msg;
    const m = await keyPair["privateKey"].decrypt(bc.hexToBigint(c));
    res.status(200).send({msg: bc.bigintToHex(m)})
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}

async function signMsg(req, res) {
  try {
    const m = bc.hexToBigint(req.body.msg);
    const s = await keyPair["privateKey"].sign(m);
    res.status(200).send({msg: bc.bigintToHex(s)})
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}

async function getMsg(req, res) {
  try {
    res.status(200).send({msg: "Hello"})
  } catch (err) {
    res.status(500).send({msg: "Something bad happened"})
  }
}

module.exports = {
  postMsg,
  signMsg,
  getMsg,
  getPublicKey
};
