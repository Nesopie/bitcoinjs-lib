import * as assert from 'assert';
import BIP32Factory from 'bip32';
import * as bip39 from 'bip39';
import * as ecc from 'tiny-secp256k1';
import { describe, it } from 'mocha';
import { PsbtInput, TapLeaf, TapLeafScript } from 'bip174/src/lib/interfaces';
import { regtestUtils } from './_regtest';
import * as bitcoin from '../..';
import { Taptree } from '../../src/types';
import { LEAF_VERSION_TAPSCRIPT } from '../../src/payments/bip341';
import { toXOnly, tapTreeToList, tapTreeFromList } from '../../src/psbt/bip371';
import { witnessStackToScriptWitness } from '../../src/psbt/psbtutils';
import { hash160, sha256, taggedHash } from '../../src/crypto';
import { toBech32 } from '../../src/address';

const rng = require('randombytes');
const regtest = regtestUtils.network;
bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);

describe('bitcoinjs-lib (transaction with taproot)', () => {
  it('can verify the BIP86 HD wallet vectors for taproot single sig (& sending example)', async () => {
    // Values taken from BIP86 document
    const mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const xprv =
      'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu';
    const path = `m/86'/0'/0'/0/0`; // Path to first child of receiving wallet on first account
    const internalPubkey = Buffer.from(
      'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115',
      'hex',
    );
    const expectedAddress =
      'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr';

    // Verify the above (Below is no different than other HD wallets)
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const rootKey = bip32.fromSeed(seed);
    assert.strictEqual(rootKey.toBase58(), xprv);
    const childNode = rootKey.derivePath(path);
    // Since internalKey is an xOnly pubkey, we drop the DER header byte
    const childNodeXOnlyPubkey = toXOnly(childNode.publicKey);
    assert.deepEqual(childNodeXOnlyPubkey, internalPubkey);

    // This is new for taproot
    // Note: we are using mainnet here to get the correct address
    // The output is the same no matter what the network is.
    const { address, output } = bitcoin.payments.p2tr({
      internalPubkey,
    });
    assert(output);
    assert.strictEqual(address, expectedAddress);
    // Used for signing, since the output and address are using a tweaked key
    // We must tweak the signer in the same way.
    const tweakedChildNode = childNode.tweak(
      bitcoin.crypto.taggedHash('TapTweak', childNodeXOnlyPubkey),
    );

    // amount from faucet
    const amount = 42e4;
    // amount to send
    const sendAmount = amount - 1e4;
    // Send some sats to the address via faucet. Get the hash and index. (txid/vout)
    const { txId: hash, vout: index } = await regtestUtils.faucetComplex(
      output,
      amount,
    );
    // Sent 420000 sats to taproot address

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput({
        hash,
        index,
        witnessUtxo: { value: amount, script: output },
        tapInternalKey: childNodeXOnlyPubkey,
      })
      .addOutput({
        value: sendAmount,
        address: regtestUtils.RANDOM_ADDRESS,
      })
      .signInput(0, tweakedChildNode)
      .finalizeAllInputs();

    const tx = psbt.extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
    await regtestUtils.verify({
      txId: tx.getId(),
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: sendAmount,
    });
  });

  it('can create (and broadcast via 3PBP) a taproot key-path spend Transaction', async () => {
    const internalKey = bip32.fromSeed(rng(64), regtest);
    const p2pkhKey = bip32.fromSeed(rng(64), regtest);

    const { output } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      network: regtest,
    });

    const { output: p2pkhOutput } = bitcoin.payments.p2pkh({
      pubkey: p2pkhKey.publicKey,
      network: regtest,
    });

    // amount from faucet
    const amount = 42e4;
    // amount to send
    const sendAmount = amount - 1e4;
    // get faucet
    const unspent = await regtestUtils.faucetComplex(output!, amount);

    // non segwit utxo
    const p2pkhUnspent = await regtestUtils.faucetComplex(p2pkhOutput!, amount);
    const utx = await regtestUtils.fetch(p2pkhUnspent.txId);
    const nonWitnessUtxo = Buffer.from(utx.txHex, 'hex');

    const psbt = new bitcoin.Psbt({ network: regtest });
    psbt.addInput({
      hash: unspent.txId,
      index: 0,
      witnessUtxo: { value: amount, script: output! },
      tapInternalKey: toXOnly(internalKey.publicKey),
    });
    psbt.addInput({ index: 0, hash: p2pkhUnspent.txId, nonWitnessUtxo });

    const sendInternalKey = bip32.fromSeed(rng(64), regtest);
    const sendPubKey = toXOnly(sendInternalKey.publicKey);
    const { address: sendAddress } = bitcoin.payments.p2tr({
      internalPubkey: sendPubKey,
      network: regtest,
    });

    psbt.addOutput({
      value: sendAmount,
      address: sendAddress!,
      tapInternalKey: sendPubKey,
    });

    const tweakedSigner = internalKey.tweak(
      bitcoin.crypto.taggedHash('TapTweak', toXOnly(internalKey.publicKey)),
    );
    await psbt.signInputAsync(0, tweakedSigner);
    await psbt.signInputAsync(1, p2pkhKey);

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const rawTx = tx.toBuffer();

    const hex = rawTx.toString('hex');

    await regtestUtils.broadcast(hex);
    await regtestUtils.verify({
      txId: tx.getId(),
      address: sendAddress!,
      vout: 0,
      value: sendAmount,
    });
  });

  it('can create (and broadcast via 3PBP) a taproot key-path spend Transaction (with unused scriptTree)', async () => {
    const internalKey = bip32.fromSeed(rng(64), regtest);
    const leafKey = bip32.fromSeed(rng(64), regtest);

    const leafScriptAsm = `${toXOnly(leafKey.publicKey).toString(
      'hex',
    )} OP_CHECKSIG`;
    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree = {
      output: leafScript,
    };

    const { output, address, hash } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      scriptTree,
      network: regtest,
    });

    // amount from faucet
    const amount = 42e4;
    // amount to send
    const sendAmount = amount - 1e4;
    // get faucet
    const unspent = await regtestUtils.faucetComplex(output!, amount);

    const psbt = new bitcoin.Psbt({ network: regtest });
    psbt.addInput({
      hash: unspent.txId,
      index: 0,
      witnessUtxo: { value: amount, script: output! },
      tapInternalKey: toXOnly(internalKey.publicKey),
      tapMerkleRoot: hash,
    });
    psbt.addOutput({ value: sendAmount, address: address! });

    const tweakedSigner = internalKey.tweak(
      bitcoin.crypto.taggedHash(
        'TapTweak',
        Buffer.concat([toXOnly(internalKey.publicKey), hash!]),
      ),
    );
    psbt.signInput(0, tweakedSigner);

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const rawTx = tx.toBuffer();

    const hex = rawTx.toString('hex');

    await regtestUtils.broadcast(hex);
    await regtestUtils.verify({
      txId: tx.getId(),
      address: address!,
      vout: 0,
      value: sendAmount,
    });
  });

  it.only('can create (and broadcast via 3PBP) a taproot script-path spend Transaction - OP_CHECKSIG', async () => {
    const internalKey = bip32.fromSeed(rng(64), regtest);
    const secret = sha256(Buffer.from('secret', 'utf8'));
    const secretHash = sha256(secret);

    const hashlockScript = createHashlock(
      secretHash,
      hash160(toXOnly(internalKey.publicKey)),
    );

    const scripts = [hashlockScript, hashlockScript];

    const merkleProof = generateMerkleProof(scripts, 0);
    const mastRoot = computeMerkleProof(
      serializeScript(hashlockScript),
      merkleProof,
    );

    const tweak = taggedHash(
      'TapTweak',
      Buffer.concat([toXOnly(internalKey.publicKey), mastRoot]),
    );

    const externalPubKey = ecc.xOnlyPointAddTweak(
      toXOnly(internalKey.publicKey),
      tweak,
    );

    const taprootAddress = toBech32(
      Buffer.from(externalPubKey?.xOnlyPubkey!),
      1,
      'bcrt',
    );

    const output = bitcoin.address.toOutputScript(taprootAddress, regtest);

    // amount from faucet
    const amount = 42e4;
    // amount to send
    // const sendAmount = amount - 1e4;
    // get faucet
    const unspent = await regtestUtils.faucetComplex(output!, amount);
    const txid = unspent.txId;

    const tx = new bitcoin.Transaction();

    tx.version = 2;

    tx.addInput(Buffer.from(txid, 'hex').reverse(), 0);

    const spk = bitcoin.address.toOutputScript(taprootAddress, regtest);

    tx.addOutput(spk, 1000);

    const hashtype = bitcoin.Transaction.SIGHASH_ALL;

    const hash = tx.hashForWitnessV1(
      0,
      [spk],
      [42e4],
      hashtype,
      taggedHash('TapLeaf', serializeScript(hashlockScript)),
    );

    const signature = ecc.signSchnorr(hash, internalKey.privateKey!);
    // console.log(
    //   'schnorr verify',
    //   ecc.verifySchnorr(hash, internalKey.publicKey, signature),
    // );

    tx.setWitness(0, [
      Buffer.concat([
        Buffer.from(signature),
        Buffer.from(hashtype.toString(16), 'hex'),
      ]),
      toXOnly(internalKey.publicKey),
      secret,
      hashlockScript,
      Buffer.concat([
        Buffer.from((0xc0 + externalPubKey!.parity).toString(16), 'hex'),
        toXOnly(internalKey.publicKey),
        ...merkleProof,
      ]),
    ]);

    try {
      await regtestUtils.broadcast(tx.toHex());
    } catch (err) {
      console.log((err as Error).message);
    }
  });

  it('can create (and broadcast via 3PBP) a taproot script-path spend Transaction - OP_CHECKSEQUENCEVERIFY', async () => {
    const internalKey = bip32.fromSeed(rng(64), regtest);
    const leafKey = bip32.fromSeed(rng(64), regtest);
    const leafPubkey = toXOnly(leafKey.publicKey).toString('hex');

    const leafScriptAsm = `OP_10 OP_CHECKSEQUENCEVERIFY OP_DROP ${leafPubkey} OP_CHECKSIG`;
    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree: Taptree = [
      {
        output: bitcoin.script.fromASM(
          '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 OP_CHECKSIG',
        ),
      },
      [
        {
          output: bitcoin.script.fromASM(
            '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 OP_CHECKSIG',
          ),
        },
        {
          output: leafScript,
        },
      ],
    ];
    const redeem = {
      output: leafScript,
      redeemVersion: LEAF_VERSION_TAPSCRIPT,
    };

    const { output, witness } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      scriptTree,
      redeem,
      network: regtest,
    });

    // amount from faucet
    const amount = 42e4;
    // amount to send
    const sendAmount = amount - 1e4;
    // get faucet
    const unspent = await regtestUtils.faucetComplex(output!, amount);

    const psbt = new bitcoin.Psbt({ network: regtest });
    psbt.addInput({
      hash: unspent.txId,
      index: 0,
      sequence: 10,
      witnessUtxo: { value: amount, script: output! },
    });
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: redeem.redeemVersion,
          script: redeem.output,
          controlBlock: witness![witness!.length - 1],
        },
      ],
    });

    const sendInternalKey = bip32.fromSeed(rng(64), regtest);
    const sendPubKey = toXOnly(sendInternalKey.publicKey);
    const { address: sendAddress } = bitcoin.payments.p2tr({
      internalPubkey: sendPubKey,
      scriptTree,
      network: regtest,
    });

    psbt.addOutput({ value: sendAmount, address: sendAddress! });
    // just to test that updateOutput works as expected
    psbt.updateOutput(0, {
      tapInternalKey: sendPubKey,
      tapTree: { leaves: tapTreeToList(scriptTree) },
    });

    await psbt.signInputAsync(0, leafKey);

    psbt.finalizeInput(0);
    const tx = psbt.extractTransaction();
    const rawTx = tx.toBuffer();
    const hex = rawTx.toString('hex');

    try {
      // broadcast before the confirmation period has expired
      await regtestUtils.broadcast(hex);
      throw new Error('Broadcast should fail.');
    } catch (err) {
      if ((err as any).message !== 'non-BIP68-final')
        throw new Error(
          'Expected OP_CHECKSEQUENCEVERIFY validation to fail. But it faild with: ' +
            err,
        );
    }
    await regtestUtils.mine(10);
    await regtestUtils.broadcast(hex);
    await regtestUtils.verify({
      txId: tx.getId(),
      address: sendAddress!,
      vout: 0,
      value: sendAmount,
    });
  });

  it('can create (and broadcast via 3PBP) a taproot script-path spend Transaction - OP_CHECKSIGADD (3-of-3)', async () => {
    const internalKey = bip32.fromSeed(rng(64), regtest);

    const leafKeys = [];
    const leafPubkeys = [];
    for (let i = 0; i < 3; i++) {
      const leafKey = bip32.fromSeed(rng(64), regtest);
      leafKeys.push(leafKey);
      leafPubkeys.push(toXOnly(leafKey.publicKey).toString('hex'));
    }

    const leafScriptAsm = `${leafPubkeys[2]} OP_CHECKSIG ${leafPubkeys[1]} OP_CHECKSIGADD ${leafPubkeys[0]} OP_CHECKSIGADD OP_3 OP_NUMEQUAL`;

    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree: Taptree = [
      {
        output: bitcoin.script.fromASM(
          '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 OP_CHECKSIG',
        ),
      },
      [
        {
          output: bitcoin.script.fromASM(
            '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 OP_CHECKSIG',
          ),
        },
        {
          output: leafScript,
        },
      ],
    ];
    const redeem = {
      output: leafScript,
      redeemVersion: LEAF_VERSION_TAPSCRIPT,
    };

    const { output, address, witness } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      scriptTree,
      redeem,
      network: regtest,
    });

    // amount from faucet
    const amount = 42e4;
    // amount to send
    const sendAmount = amount - 1e4;
    // get faucet
    const unspent = await regtestUtils.faucetComplex(output!, amount);

    const psbt = new bitcoin.Psbt({ network: regtest });
    psbt.addInput({
      hash: unspent.txId,
      index: 0,
      witnessUtxo: { value: amount, script: output! },
    });
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: redeem.redeemVersion,
          script: redeem.output,
          controlBlock: witness![witness!.length - 1],
        },
      ],
    });

    psbt.addOutput({ value: sendAmount, address: address! });

    // random order for signers
    psbt.signInput(0, leafKeys[1]);
    psbt.signInput(0, leafKeys[2]);
    psbt.signInput(0, leafKeys[0]);

    psbt.finalizeInput(0);
    const tx = psbt.extractTransaction();
    const rawTx = tx.toBuffer();
    const hex = rawTx.toString('hex');

    await regtestUtils.broadcast(hex);
    await regtestUtils.verify({
      txId: tx.getId(),
      address: address!,
      vout: 0,
      value: sendAmount,
    });
  });

  it('can create (and broadcast via 3PBP) a taproot script-path spend Transaction - custom finalizer', async () => {
    const leafCount = 8;
    const leaves = Array.from({ length: leafCount }).map(
      (_, index) =>
        ({
          depth: 3,
          leafVersion: LEAF_VERSION_TAPSCRIPT,
          script: bitcoin.script.fromASM(`OP_ADD OP_${index * 2} OP_EQUAL`),
        } as TapLeaf),
    );
    const scriptTree = tapTreeFromList(leaves);

    for (let leafIndex = 1; leafIndex < leafCount; leafIndex++) {
      const redeem = {
        output: bitcoin.script.fromASM(`OP_ADD OP_${leafIndex * 2} OP_EQUAL`),
        redeemVersion: LEAF_VERSION_TAPSCRIPT,
      };

      const internalKey = bip32.fromSeed(rng(64), regtest);
      const { output, witness } = bitcoin.payments.p2tr({
        internalPubkey: toXOnly(internalKey.publicKey),
        scriptTree,
        redeem,
        network: regtest,
      });

      // amount from faucet
      const amount = 42e4;
      // amount to send
      const sendAmount = amount - 1e4;
      // get faucet
      const unspent = await regtestUtils.faucetComplex(output!, amount);

      const psbt = new bitcoin.Psbt({ network: regtest });
      psbt.addInput({
        hash: unspent.txId,
        index: 0,
        witnessUtxo: { value: amount, script: output! },
      });

      const tapLeafScript: TapLeafScript = {
        leafVersion: redeem.redeemVersion,
        script: redeem.output,
        controlBlock: witness![witness!.length - 1],
      };
      psbt.updateInput(0, { tapLeafScript: [tapLeafScript] });

      const sendAddress =
        'bcrt1pqknex3jwpsaatu5e5dcjw70nac3fr5k5y3hcxr4hgg6rljzp59nqs6a0vh';
      psbt.addOutput({
        value: sendAmount,
        address: sendAddress,
      });

      const leafIndexFinalizerFn = buildLeafIndexFinalizer(
        tapLeafScript,
        leafIndex,
      );
      psbt.finalizeInput(0, leafIndexFinalizerFn);
      const tx = psbt.extractTransaction();
      const rawTx = tx.toBuffer();
      const hex = rawTx.toString('hex');

      await regtestUtils.broadcast(hex);
      await regtestUtils.verify({
        txId: tx.getId(),
        address: sendAddress!,
        vout: 0,
        value: sendAmount,
      });
    }
  });

  it('should fail validating invalid signatures for taproot (See issue #1931)', () => {
    const schnorrValidator = (
      pubkey: Buffer,
      msghash: Buffer,
      signature: Buffer,
    ) => {
      return ecc.verifySchnorr(msghash, pubkey, signature);
    };

    const psbtBase64 =
      `cHNidP8BAFICAAAAAe1h73A6zedruNERV6JU7Ty1IlYZh2KO1cBklZqCMEy8AAAAAAD/////ARA
      nAAAAAAAAFgAUS0GlfqWSeEWIpwPwrvRIjBbJQroAAAAAAAEA/TgBAQAAAAABAnGJ6st1FIvYLEV
      bJMQaZ3HSOJnkw5C+ViCuJYiFEYosAAAAAAD9////xuZd0xArNSaBuElLX3nzjwtZW95O7L/wbz9
      4v+v0vuYAAAAAAP3///8CECcAAAAAAAAiUSAVbMSHgwYVdyBgfNy0syr6TMaFOGhFjXJYuQcRLlp
      DS8hgBwAAAAAAIlEgthWGz3o2R7WpgjIK52ODoEaA/0HcImSUjVk6agZgghwBQIP9WWErMfeBBYy
      uHuSZS7MdXVICtlFgNveDrvuXeQGSZl1gGG6/r3Aw7h9TifGtoA+7JwYBjLMcEG6hbeyQGXIBQNS
      qKH1p/NFzO9bxe9vpvBZQIaX5Qa9SY2NfNCgSRNabmX5EiaihWcLC+ALgchm7DUfYrAmi1r4uSI/
      YaQ1lq8gAAAAAAQErECcAAAAAAAAiUSAVbMSHgwYVdyBgfNy0syr6TMaFOGhFjXJYuQcRLlpDSwE
      DBIMAAAABCEMBQZUpv6e1Hwfpi/PpglkkK/Rx40vZIIHwtJ7dXWFZ5TcZUEelCnfKOAWZ4xWjauY
      M2y+JcgFcVsuPzPuiM+z5AH+DARNBlSm/p7UfB+mL8+mCWSQr9HHjS9kggfC0nt1dYVnlNxlQR6U
      Kd8o4BZnjFaNq5gzbL4lyAVxWy4/M+6Iz7PkAf4MBFyC6ZCT2zZVrEbkw/T1fyS8eLKQaP2MH6rz
      dlMauGvQzLQAA`.replace(/\s+/g, '');

    const psbt = bitcoin.Psbt.fromBase64(psbtBase64);

    assert(
      !psbt.validateSignaturesOfAllInputs(schnorrValidator),
      'Should fail validation',
    );
  });

  it('should succeed validating valid signatures for taproot (See issue #1934)', () => {
    const schnorrValidator = (
      pubkey: Buffer,
      msghash: Buffer,
      signature: Buffer,
    ) => {
      return ecc.verifySchnorr(msghash, pubkey, signature);
    };

    const psbtBase64 =
      `cHNidP8BAF4CAAAAAU6UzYPa7tES0HoS+obnRJuXX41Ob64Zs59qDEyKsu1ZAAAAAAD/////AYA
      zAjsAAAAAIlEgIlIzfR+flIWYTyewD9v+1N84IubZ/7qg6oHlYLzv1aYAAAAAAAEAXgEAAAAB8f+
      afEJBun7sRQLFE1Olc/gK9LBaduUpz3vB4fjXVF0AAAAAAP3///8BECcAAAAAAAAiUSAiUjN9H5+
      UhZhPJ7AP2/7U3zgi5tn/uqDqgeVgvO/VpgAAAAABASsQJwAAAAAAACJRICJSM30fn5SFmE8nsA/
      b/tTfOCLm2f+6oOqB5WC879WmAQMEgwAAAAETQWQwNOao3RMOBWPuAQ9Iph7Qzk47MvroTHbJR49
      MxKJmQ6hfhZa5wVVrdKYea5BW/loqa7al2pYYZMlGvdS06wODARcgjuYXxIpyOMVTYEvl35gDidC
      m/vUICZyuNNZKaPz9dxAAAQUgjuYXxIpyOMVTYEvl35gDidCm/vUICZyuNNZKaPz9dxAA`.replace(
        /\s+/g,
        '',
      );

    const psbt = bitcoin.Psbt.fromBase64(psbtBase64);

    assert(
      psbt.validateSignaturesOfAllInputs(schnorrValidator),
      'Should succeed validation',
    );
  });
});

function buildLeafIndexFinalizer(
  tapLeafScript: TapLeafScript,
  leafIndex: number,
): (
  inputIndex: number,
  _input: PsbtInput,
  _tapLeafHashToFinalize?: Buffer,
) => {
  finalScriptWitness: Buffer | undefined;
} {
  return (
    inputIndex: number,
    _input: PsbtInput,
    _tapLeafHashToFinalize?: Buffer,
  ): {
    finalScriptWitness: Buffer | undefined;
  } => {
    try {
      const scriptSolution = [
        Buffer.from([leafIndex]),
        Buffer.from([leafIndex]),
      ];
      const witness = scriptSolution
        .concat(tapLeafScript.script)
        .concat(tapLeafScript.controlBlock);
      return { finalScriptWitness: witnessStackToScriptWitness(witness) };
    } catch (err) {
      throw new Error(`Can not finalize taproot input #${inputIndex}: ${err}`);
    }
  };
}

export const createTapTree = (scripts: Buffer[]) => {
  let currentLevel = scripts.map(script =>
    taggedHash('TapLeaf', serializeScript(script)),
  );

  while (currentLevel.length != 1) {
    let nextLevel = [] as Buffer[];
    const maxNodes = Math.pow(2, Math.floor(Math.log2(currentLevel.length)));
    for (let i = 0; i < maxNodes; i += 2) {
      const [smaller, bigger] = currentLevel
        .slice(i, i + 2)
        .sort((a, b) => a.compare(b));

      nextLevel.push(taggedHash('TapBranch', Buffer.concat([smaller, bigger])));
    }
    currentLevel = [...nextLevel, ...currentLevel.slice(maxNodes)];
  }

  return currentLevel;
};

const LEAF_VERSION = Buffer.from('c0', 'hex');
const serializeScript = (script: Buffer) => {
  return Buffer.concat([
    LEAF_VERSION,
    Buffer.from(script.byteLength.toString(16), 'hex'), // add compact size encoding later
    script,
  ]);
};

const generateMerkleProof = (scripts: Buffer[], index: number) => {
  if (index > scripts.length - 1) throw new Error('Invalid index');

  let currentLevel = scripts.map(script =>
    taggedHash('TapLeaf', serializeScript(script)),
  );

  const proofs = [] as Buffer[];

  while (currentLevel.length != 1) {
    let nextLevel = [] as Buffer[];
    if (index < currentLevel.length) {
      if (index % 2) proofs.push(currentLevel[index - 1]);
      else proofs.push(currentLevel[index + 1]);

      index = Math.floor(index / 2);
    }
    const maxNodes = Math.pow(2, Math.floor(Math.log2(currentLevel.length)));
    for (let i = 0; i < maxNodes; i += 2) {
      const [smaller, bigger] = currentLevel
        .slice(i, i + 2)
        .sort((a, b) => a.compare(b));

      nextLevel.push(taggedHash('TapBranch', Buffer.concat([smaller, bigger])));
    }
    currentLevel = [...nextLevel, ...currentLevel.slice(maxNodes)];
  }

  return proofs;
};

export const computeMerkleProof = (leaf: Buffer, merkleProof: Buffer[]) => {
  const hash = taggedHash('TapLeaf', leaf);
  const proofHash = merkleProof.reduce(
    (acc, proof) =>
      taggedHash(
        'TapBranch',
        Buffer.concat([acc, proof].sort((a, b) => a.compare(b))),
      ),
    hash,
  );

  return proofHash;
};

export const createHashlock = (secretHash: Buffer, enabler: Buffer): Buffer => {
  const script = bitcoin.script.compile([
    bitcoin.script.OPS.OP_SHA256,
    secretHash,
    bitcoin.script.OPS.OP_EQUALVERIFY,
    bitcoin.script.OPS.OP_DUP,
    bitcoin.script.OPS.OP_HASH160,
    enabler,
    bitcoin.script.OPS.OP_EQUALVERIFY,
    bitcoin.script.OPS.OP_CHECKSIG,
  ]);

  return script;
};
