{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Ouroboros.Consensus.Shelley.Protocol.Praos () where

import qualified Cardano.Crypto.KES as KES
import Cardano.Crypto.VRF (certifiedOutput)
import Cardano.Ledger.BaseTypes (ProtVer (ProtVer), StrictMaybe (..))
import Cardano.Ledger.Chain (ChainChecksPParams (..))
import Cardano.Ledger.Keys (hashKey)
import Cardano.Ledger.Slot (SlotNo (unSlotNo))
import Cardano.Protocol.Praos.BlockHeader
  ( Header (..)
  , HeaderBody (..)
  , IssuerCert (..)
  , headerHash
  , headerSize
  )
import Cardano.Protocol.TPraos.OCert
  ( OCert (ocertKESPeriod, ocertVkHot)
  )
import qualified Cardano.Protocol.TPraos.OCert as SL
import Data.Either (isRight)
import Ouroboros.Consensus.Protocol.Praos
import Ouroboros.Consensus.Protocol.Praos.Common
  ( MaxMajorProtVer (MaxMajorProtVer)
  )
import Ouroboros.Consensus.Protocol.Praos.Views
import Ouroboros.Consensus.Protocol.Signed
import Ouroboros.Consensus.Shelley.Protocol.Abstract
  ( ProtoCrypto
  , ProtocolHeaderSupportsEnvelope (..)
  , ProtocolHeaderSupportsKES (..)
  , ProtocolHeaderSupportsProtocol (..)
  , ShelleyHash (ShelleyHash)
  , ShelleyProtocol
  , ShelleyProtocolHeader
  )
import Ouroboros.Consensus.Shelley.Protocol.EnvelopeChecks
  ( EnvelopeError
  , EnvelopeHeaderView (..)
  , envelopeCheck
  )

type instance ProtoCrypto (Praos c) = c

type instance ShelleyProtocolHeader (Praos c) = Header c

instance PraosCrypto c => ProtocolHeaderSupportsEnvelope (Praos c) where
  pHeaderHash hdr = ShelleyHash $ headerHash hdr
  pHeaderPrevHash (Header body _) = hbPrev body
  pHeaderBodyHash (Header body _) = hbBodyHash body
  pHeaderSlot (Header body _) = hbSlotNo body
  pHeaderBlock (Header body _) = hbBlockNo body
  pHeaderSize hdr = fromIntegral $ headerSize hdr
  pHeaderBlockSize (Header body _) = fromIntegral $ hbBodySize body

  type EnvelopeCheckError _ = EnvelopeError

  envelopeChecks cfg lv hdr =
    envelopeCheck maxpv ccd $
      EnvelopeHeaderView
        { ehvProtVer = m
        , ehvHeaderSize = headerSize hdr
        , ehvBodySize = hbBodySize body
        }
   where
    Header body _ = hdr
    MaxMajorProtVer maxpv = praosMaxMajorPV (praosParams cfg)
    ProtVer m _ = plvProtocolVersion lv
    ccd =
      ChainChecksPParams
        { ccMaxBHSize = plvMaxHeaderSize lv
        , ccMaxBBSize = plvMaxBodySize lv
        , ccProtocolVersion = plvProtocolVersion lv
        }

instance PraosCrypto c => ProtocolHeaderSupportsKES (Praos c) where
  configSlotsPerKESPeriod cfg = praosSlotsPerKESPeriod $ praosParams cfg
  -- A header without its certificate cannot be checked without the
  -- chain-dependent state, which this stateless integrity check does not
  -- have; such headers pass here and are fully validated by
  -- 'updateChainDepState' instead.
  verifyHeaderIntegrity slotsPerKESPeriod header =
    case hbOCert headerBody of
      SNothing -> True
      SJust (IssuerCert _ SL.OCert{ocertVkHot, ocertKESPeriod = SL.KESPeriod startOfKesPeriod}) ->
        let currentKesPeriod =
              fromIntegral $
                unSlotNo (hbSlotNo headerBody) `div` slotsPerKESPeriod
            t
              | currentKesPeriod >= startOfKesPeriod =
                  currentKesPeriod - startOfKesPeriod
              | otherwise =
                  0
         in isRight $ KES.verifySignedKES () ocertVkHot t headerBody headerSig
   where
    Header{headerBody, headerSig} = header
  mkHeader hk cbl il slotNo blockNo prevHash bbHash sz protVer = do
    PraosFields{praosSignature, praosToSign} <- forgePraosFields hk cbl il mkBhBodyBytes
    pure $ Header praosToSign praosSignature
   where
    mkBhBodyBytes
      PraosToSign
        { praosToSignIssuerVK
        , praosToSignVrfVK
        , praosToSignVrfRes
        , praosToSignOCert
        , praosToSignCarryOCert
        } =
        HeaderBody
          { hbBlockNo = blockNo
          , hbSlotNo = slotNo
          , hbPrev = prevHash
          , hbIssuer = hashKey praosToSignIssuerVK
          , hbIssueNo = SL.ocertN praosToSignOCert
          , hbVrfVk = praosToSignVrfVK
          , hbVrfRes = praosToSignVrfRes
          , hbBodySize = fromIntegral sz
          , hbBodyHash = bbHash
          , hbOCert =
              if praosToSignCarryOCert
                then SJust (IssuerCert praosToSignIssuerVK praosToSignOCert)
                else SNothing
          , hbProtVer = protVer
          }

instance PraosCrypto c => ProtocolHeaderSupportsProtocol (Praos c) where
  type CannotForgeError (Praos c) = PraosCannotForge c
  protocolHeaderView Header{headerBody, headerSig} =
    HeaderView
      { hvPrevHash = hbPrev headerBody
      , hvIssuer = hbIssuer headerBody
      , hvIssueNo = hbIssueNo headerBody
      , hvVrfVK = hbVrfVk headerBody
      , hvVrfRes = hbVrfRes headerBody
      , hvOCert = hbOCert headerBody
      , hvSlotNo = hbSlotNo headerBody
      , hvSigned = headerBody
      , hvSignature = headerSig
      }
  pHeaderIssuer = hbIssuer . headerBody
  pHeaderIssueNo = hbIssueNo . headerBody

  -- This is the "unified" VRF value, prior to range extension which yields e.g.
  -- the leader VRF value used for slot election.
  --
  -- In the future, we might want to use a dedicated range-extended VRF value
  -- here instead.
  pTieBreakVRFValue = certifiedOutput . hbVrfRes . headerBody

type instance Signed (Header c) = HeaderBody c
instance PraosCrypto c => SignedHeader (Header c) where
  headerSigned = headerBody

instance PraosCrypto c => ShelleyProtocol (Praos c)
