'use strict'

const { random } = require('../src/crypto')

const chai = require('chai')
const { expect } = chai
chai.should()

describe('crypto', () => {
  describe('random', () => {
    it('should return a random string', () => {
      const result = random(8) // 8 bytes / 16 chars

      expect(typeof result).to.equal('string')
      expect(result.length).to.equal(16)
    })
  })
})
