import { hash, verify } from 'argon2';

async function test() {
  try {
    const h = await hash('Password@123');
    console.log('Hash success:', h);
    const valid = await verify(h, 'Password@123');
    console.log('Verify success:', valid);
  } catch (err) {
    console.error('Argon2 failed:', err.message);
  }
}

test();
