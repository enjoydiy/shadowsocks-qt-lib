#include "SocksState.h"

SocksState::SocksState(SocksConnection *parent) :
    QObject(parent)
{
    _parent = parent;
    stage = D_INIT;
}

SocksState::~SocksState()
{
}

void SocksState::handleSetAsNewState()
{
    //default does nothing
}
