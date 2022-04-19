import strategy, { Strategy } from '..';

describe('passport-esia', () => {
  
  it('should export Strategy constructor as module', () => {
    expect(strategy).to.be.a('function');
    expect(strategy).to.equal(Strategy);
  });
  
  it('should export Strategy constructor', () => {
    expect(Strategy).to.be.a('function');
  });
  
});
