'use strict'

const { FlexDocStore } = require('flex-docstore')

function testStore () {
  return {
    clients: FlexDocStore.using('memory'),
    codes: FlexDocStore.using('memory'),
    tokens: FlexDocStore.using('memory'),
    refresh: FlexDocStore.using('memory')
  }
}

module.exports = testStore
