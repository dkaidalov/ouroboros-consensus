{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Ouroboros.Consensus.Protocol.Praos.Views
  ( HeaderView (..)
  , PraosLedgerView (..)
  , forecastToPraosLedgerView
  ) where

import Cardano.Crypto.KES (SignedKES)
import Cardano.Crypto.VRF (CertifiedVRF, VRFAlgorithm (VerKeyVRF))
import Cardano.Ledger.BaseTypes (ProtVer, StrictMaybe)
import Cardano.Ledger.Chain (ChainChecksPParams (..))
import Cardano.Ledger.Keys (KeyHash, KeyRole (BlockIssuer))
import qualified Cardano.Ledger.Shelley.API as SL
import Cardano.Protocol.Crypto (KES, VRF)
import Cardano.Protocol.Praos.BlockHeader (HeaderBody, IssuerCert)
import Cardano.Protocol.Praos.VRF (InputVRF)
import Cardano.Protocol.TPraos.BlockHeader (PrevHash)
import Cardano.Slotting.Slot (SlotNo)
import Data.Word (Word16, Word32, Word64)
import Lens.Micro ((^.))

-- | View of the block header required by the Praos protocol.
data HeaderView crypto = HeaderView
  { hvPrevHash :: !PrevHash
  -- ^ Hash of the previous block
  , hvIssuer :: !(KeyHash BlockIssuer)
  -- ^ hash of the block issuer's cold verification key
  , hvIssueNo :: !Word64
  -- ^ counter of the operational certificate in force
  , hvVrfVK :: !(VerKeyVRF (VRF crypto))
  -- ^ VRF verification key for block issuer
  , hvVrfRes :: !(CertifiedVRF (VRF crypto) InputVRF)
  -- ^ VRF result
  , hvOCert :: !(StrictMaybe (IssuerCert crypto))
  -- ^ cold key and operational certificate, when the header carries them
  , hvSlotNo :: !SlotNo
  -- ^ Slot
  , hvSigned :: !(HeaderBody crypto)
  -- ^ Header which must be signed
  , hvSignature :: !(SignedKES (KES crypto) (HeaderBody crypto))
  -- ^ KES Signature of the header
  }

data PraosLedgerView = PraosLedgerView
  { plvPoolDistr :: SL.PoolDistr
  -- ^ Stake distribution
  , plvMaxHeaderSize :: !Word16
  -- ^ Maximum header size
  , plvMaxBodySize :: !Word32
  -- ^ Maximum block body size
  , plvProtocolVersion :: !ProtVer
  -- ^ Current protocol version
  }
  deriving Show

-- | Build a 'PraosLedgerView' from a ledger 'EraForecast'
forecastToPraosLedgerView ::
  forall t era.
  SL.EraForecast era =>
  SL.Forecast t era ->
  PraosLedgerView
forecastToPraosLedgerView f =
  PraosLedgerView
    { plvPoolDistr = f ^. SL.poolDistrForecastL @era @t
    , plvMaxHeaderSize = ccMaxBHSize cc
    , plvMaxBodySize = ccMaxBBSize cc
    , plvProtocolVersion = ccProtocolVersion cc
    }
 where
  cc = SL.forecastChainChecks @t @era f
