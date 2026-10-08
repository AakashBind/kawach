import { validateUrlForSSRF } from '../src/services/ssrfValidator';

describe('SSRF Protection Security Tests', () => {
  test('should block localhost and 127.0.0.1', async () => {
    const res1 = await validateUrlForSSRF('http://localhost:8080/admin');
    expect(res1.allowed).toBe(false);

    const res2 = await validateUrlForSSRF('http://127.0.0.1:5000/internal');
    expect(res2.allowed).toBe(false);
  });

  test('should block AWS / cloud metadata IP (169.254.169.254)', async () => {
    const res = await validateUrlForSSRF('http://169.254.169.254/latest/meta-data/');
    expect(res.allowed).toBe(false);
  });

  test('should block private RFC 1918 networks (10.x, 192.168.x, 172.16.x)', async () => {
    const res1 = await validateUrlForSSRF('http://10.0.0.1/dashboard');
    expect(res1.allowed).toBe(false);

    const res2 = await validateUrlForSSRF('http://192.168.1.1/router');
    expect(res2.allowed).toBe(false);

    const res3 = await validateUrlForSSRF('http://172.16.0.5/');
    expect(res3.allowed).toBe(false);
  });

  test('should block forbidden protocols (file://, ftp://, gopher://, javascript:)', async () => {
    const res1 = await validateUrlForSSRF('file:///etc/passwd');
    expect(res1.allowed).toBe(false);

    const res2 = await validateUrlForSSRF('gopher://127.0.0.1:70');
    expect(res2.allowed).toBe(false);
  });

  test('should allow public benign URLs (google.com, example.com)', async () => {
    const res = await validateUrlForSSRF('https://example.com');
    expect(res.allowed).toBe(true);
  });
});
