import { Test, TestingModule } from '@nestjs/testing';
import { configuration } from './configuration';

describe('Configuration', () => {
  let config = configuration();

  describe('Check Application valibale Configuration', () => {
    it('should return Port', () => {
      expect(config.app.port).toBe(8080);
    });
    it('should return NODE_ENV', () => {
        expect(config.app.node_env).toBe('test');
      });
  });

  describe('Check HTTP valibale Configuration', () => {
    it('should return timeout', () => {
      expect(config.http.timeout).toBe(5000);
    });
    it('should return max_redirects', () => {
        expect(config.http.max_redirects).toBe(5);
      });
  });

  describe('Check Error valibale Configuration', () => {
    it('should return sentry', () => {
      expect(config.error.sentry).toBeDefined();
    });
  });
});
