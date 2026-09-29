import { test } from 'node:test';
import assert from 'node:assert/strict';
import { phpFixture } from './php-runtime.mjs';

const id = 'a'.repeat(64), otherId = 'b'.repeat(64);
const files = suffix => ({ certificateFile: 'ssl-certificate-' + suffix.repeat(16) + '-' + suffix.repeat(12) + '.php', privateKeyFile: 'ssl-private-key-' + suffix.repeat(16) + '-' + suffix.repeat(12) + '.php' });

test('Delete removes only the chosen PHP record, its pending renewal and saved files, retaining login, account and other records', async t => {
  const f = await phpFixture({ installDirectory: '/site/tools/freessl' }); t.after(() => f.php.exit());
  const root = '/site/tools/freessl', chosenFiles = files('a'), otherFiles = files('b');
  const account = { fixture: 'account-kept' }, terms = { production: 'agreed-terms-kept' };
  f.configure({ records: { [id]: { id, domains: ['example.com'], ...chosenFiles }, [otherId]: { id: otherId, domains: ['example.com'], ...otherFiles } },
    pending: { [id]: { id, domains: ['example.com'], environment: 'production', resources: [] } }, accounts: account, agreedTerms: terms });
  for (const name of Object.values({ ...chosenFiles, otherCertificate: otherFiles.certificateFile, otherKey: otherFiles.privateKeyFile })) f.php.writeFile(root + '/' + name, f.guard + 'isolated-fixture');
  const before = f.php.readFileAsText(root + '/ssl-helper.config.php');
  assert.equal((await f.request('delete', { id }, { headers: { Cookie: '' } })).status, 403);
  assert.equal((await f.request('delete', { id }, { server: { HTTP_SEC_FETCH_SITE: 'cross-site' } })).status, 403);
  assert.equal((await f.request('delete', { id: '../../freessl-password.php' })).status, 400);
  assert.equal((await f.request('delete', { id: 'c'.repeat(64) })).status, 404);
  assert.equal(f.php.readFileAsText(root + '/ssl-helper.config.php'), before);
  const deleted = await f.request('delete', { id });
  assert.equal(deleted.status, 200, deleted.raw + deleted.errors);
  assert.deepEqual(deleted.body.records.map(record => record.id), [otherId]);
  assert.equal(f.php.fileExists(root + '/' + chosenFiles.certificateFile), false);
  assert.equal(f.php.fileExists(root + '/' + chosenFiles.privateKeyFile), false);
  assert.equal(f.php.fileExists(root + '/' + otherFiles.certificateFile), true);
  assert.equal(f.php.fileExists(root + '/' + otherFiles.privateKeyFile), true);
  assert.equal((await f.request('result', { id })).status, 404);
  assert.equal((await f.request('pending', { id })).status, 404);
  const reopened = await f.request('status');
  assert.equal(reopened.body.authenticated, true);
  assert.deepEqual(reopened.body.records.map(record => record.id), [otherId]);
  const saved = JSON.parse(f.php.readFileAsText(root + '/ssl-helper.config.php').slice(f.guard.length));
  assert.equal(saved.pending[id], undefined);
  assert.deepEqual(saved.accounts, account); assert.deepEqual(saved.agreedTerms, terms);
});

test('Delete removes a pending-only PHP entry and refuses a record pointing at unrelated files', async t => {
  const f = await phpFixture(); t.after(() => f.php.exit());
  f.configure({ records: { [id]: { id, domains: ['example.com'], certificateFile: '../keep.php' } },
    pending: { [otherId]: { id: otherId, domains: ['pending.example.com'], environment: 'production', resources: [] } } });
  f.php.writeFile('/keep.php', 'untouched');
  assert.equal((await f.request('delete', { id })).status, 409);
  assert.equal(f.php.readFileAsText('/keep.php'), 'untouched');
  const deleted = await f.request('delete', { id: otherId });
  assert.equal(deleted.status, 200, deleted.raw + deleted.errors);
  assert.deepEqual(deleted.body.records.map(record => record.id), [id]);
  assert.equal((await f.request('pending', { id: otherId })).status, 404);
});
