package MyBuilder;
use base 'Module::Build';
use warnings;
use strict;
use Config;
use Carp;
use Config::AutoConf;

use File::Spec::Functions qw.catdir catfile.;
use File::Path qw.mkpath.;

my @SOURCES = (
   qw{
	asn1/AbsentSubscriberDiagnosticSM.c
	asn1/AbsentSubscriberParam.c
	asn1/AbsentSubscriberReason.c
	asn1/AbsentSubscriberSM-Param.c
	asn1/AccessNetworkProtocolId.c
	asn1/AccessNetworkSignalInfo.c
	asn1/AccessRestrictionData.c
	asn1/AccessType.c
	asn1/Accuracy.c
	asn1/AccuracyFulfilmentIndicator.c
	asn1/AccuracyOpt.c
	asn1/AcquisAssist.c
	asn1/AcquisElement.c
	asn1/ActivateTraceModeArg.c
	asn1/ActivateTraceModeRes.c
	asn1/Add-GeographicalInformation.c
	asn1/Add-GPS-AssistData.c
	asn1/Add-GPS-ControlHeader.c
	asn1/ADD-Info.c
	asn1/AddionalAngleFields.c
	asn1/AddionalDopplerFields.c
	asn1/AdditionalAssistanceData.c
	asn1/AdditionalDopplerFields.c
	asn1/AdditionalInfo.c
	asn1/AdditionalNetworkResource.c
	asn1/Additional-Number.c
	asn1/AdditionalRequestedCAMEL-SubscriptionInfo.c
	asn1/AdditionalRoamingNotAllowedCause.c
	asn1/AdditionalSubscriptions.c
	asn1/AddressString.c
	asn1/AgeIndicator.c
	asn1/AgeOfLocationInformation.c
	asn1/AlertFlag.c
	asn1/AlertingPattern.c
	asn1/AlertReason.c
	asn1/AlertServiceCentreArg.c
	asn1/Allocation-Retention-Priority.c
	asn1/AllowedGSM-Algorithms.c
	asn1/AllowedUMTS-Algorithms.c
	asn1/Almanac.c
	asn1/Almanac-ECEFsbasAlmanacSet.c
	asn1/AlmanacElement.c
	asn1/Almanac-GlonassAlmanacSet.c
	asn1/Almanac-KeplerianSet.c
	asn1/Almanac-MidiAlmanacSet.c
	asn1/Almanac-NAVKeplerianSet.c
	asn1/Almanac-ReducedKeplerianSet.c
	asn1/AltitudeInfo.c
	asn1/AMBR.c
	asn1/AntiSpoofFlag.c
	asn1/ANY.c
	asn1/AnyTimeInterrogationArg.c
	asn1/AnyTimeInterrogationRes.c
	asn1/AnyTimeModificationArg.c
	asn1/AnyTimeModificationRes.c
	asn1/AnyTimeSubscriptionInterrogationArg.c
	asn1/AnyTimeSubscriptionInterrogationRes.c
	asn1/AoIPCodec.c
	asn1/AoIPCodecsList.c
	asn1/APN.c
	asn1/APN-Configuration.c
	asn1/APN-ConfigurationProfile.c
	asn1/APN-OI-Replacement.c
	asn1/Area.c
	asn1/AreaDefinition.c
	asn1/AreaEventInfo.c
	asn1/AreaIdentification.c
	asn1/AreaList.c
	asn1/AreaScope.c
	asn1/AreaType.c
	asn1/ASCI-CallReference.c
	asn1/asn_codecs_prim.c
	asn1/asn_SEQUENCE_OF.c
	asn1/asn_SET_OF.c
	asn1/AssistanceData.c
	asn1/AssistanceNeeded.c
	asn1/AssistanceSupported.c
	asn1/AssistBTSData.c
	asn1/AssistBTSData-R98-ExpOTD.c
	asn1/ATI-NotAllowedParam.c
	asn1/ATM-NotAllowedParam.c
	asn1/ATSI-NotAllowedParam.c
	asn1/AuthenticationFailureReportArg.c
	asn1/AuthenticationFailureReportRes.c
	asn1/AuthenticationQuintuplet.c
	asn1/AuthenticationSetList.c
	asn1/AuthenticationTriplet.c
	asn1/AUTN.c
	asn1/AUTS.c
	asn1/BadSignalElement.c
	asn1/Bandwidth.c
	asn1/BasicServiceCode.c
	asn1/BasicServiceCriteria.c
	asn1/BasicServiceGroupList.c
	asn1/BasicServiceList.c
	asn1/BCCHCarrier.c
	asn1/BearerServiceCode.c
	asn1/BearerServiceList.c
	asn1/BearerServNotProvParam.c
	asn1/ber_decoder.c
	asn1/ber_tlv_length.c
	asn1/ber_tlv_tag.c
	asn1/BitNumber.c
	asn1/BIT_STRING.c
	asn1/BMSC-EventList.c
	asn1/BMSC-InterfaceList.c
	asn1/BOOLEAN.c
	asn1/BSICAndCarrier.c
	asn1/BSIC.c
	asn1/BSSMAP-ServiceHandover.c
	asn1/BSSMAP-ServiceHandoverInfo.c
	asn1/BSSMAP-ServiceHandoverList.c
	asn1/BTSPosition.c
	asn1/BusySubscriberParam.c
	asn1/CalcAssistanceBTS.c
	asn1/CallBarredParam.c
	asn1/CallBarringCause.c
	asn1/CallBarringData.c
	asn1/CallBarringFeature.c
	asn1/CallBarringFeatureList.c
	asn1/CallBarringInfo.c
	asn1/CallForwardingData.c
	asn1/CallHoldData.c
	asn1/CallTypeCriteria.c
	asn1/CallWaitingData.c
	asn1/CamelCapabilityHandling.c
	asn1/CAMEL-SubscriptionInfo.c
	asn1/CancellationType.c
	asn1/CancelLocationArg.c
	asn1/CancelLocationRes.c
	asn1/Category.c
	asn1/CauseValue.c
	asn1/CCBS-Data.c
	asn1/CCBS-Feature.c
	asn1/CCBS-FeatureList.c
	asn1/CCBS-Index.c
	asn1/CCBS-RequestState.c
	asn1/CdmaCellInformation.c
	asn1/CellGlobalIdOrServiceAreaIdFixedLength.c
	asn1/CellGlobalIdOrServiceAreaIdOrLAI.c
	asn1/CellIDAndLAC.c
	asn1/CellID.c
	asn1/CellInfo.c
	asn1/CellMeasuredResults.c
	asn1/CellMeasuredResultsList.c
	asn1/CellParametersID.c
	asn1/CGI-List.c
	asn1/ChargingCharacteristics.c
	asn1/CheckIMEI-Arg.c
	asn1/CheckIMEI-Res.c
	asn1/ChosenChannelInfo.c
	asn1/ChosenEncryptionAlgorithm.c
	asn1/ChosenIntegrityProtectionAlgorithm.c
	asn1/ChosenRadioResourceInformation.c
	asn1/ChosenSpeechVersion.c
	asn1/CK.c
	asn1/Cksn.c
	asn1/ClipData.c
	asn1/ClirData.c
	asn1/CliRestrictionOption.c
	asn1/CNAVclockModel.c
	asn1/Codec.c
	asn1/CodecList.c
	asn1/CommonGANSSAssistance.c
	asn1/constraints.c
	asn1/constr_CHOICE.c
	asn1/constr_SEQUENCE.c
	asn1/constr_SEQUENCE_OF.c
	asn1/constr_SET_OF.c
	asn1/constr_TYPE.c
	asn1/ContextId.c
	asn1/ContextIdList.c
	asn1/ControlHeader.c
	asn1/CPICH-Ec-N0.c
	asn1/CPICH-RSCP.c
	asn1/CS-AllocationRetentionPriority.c
	asn1/CSG-Id.c
	asn1/CSG-SubscriptionData.c
	asn1/CSG-SubscriptionDataList.c
	asn1/CUG-Feature.c
	asn1/CUG-FeatureList.c
	asn1/CUG-Index.c
	asn1/CUG-Info.c
	asn1/CUG-Interlock.c
	asn1/CUG-RejectCause.c
	asn1/CUG-RejectParam.c
	asn1/CUG-Subscription.c
	asn1/CUG-SubscriptionList.c
	asn1/CurrentSecurityContext.c
	asn1/DataMissingParam.c
	asn1/D-CSI.c
	asn1/DeactivateTraceModeArg.c
	asn1/DeactivateTraceModeRes.c
	asn1/DefaultCallHandling.c
	asn1/DefaultGPRS-Handling.c
	asn1/DefaultSMS-Handling.c
	asn1/DeferredLocationEventType.c
	asn1/Deferredmt-lrData.c
	asn1/DeleteSubscriberDataArg.c
	asn1/DeleteSubscriberDataRes.c
	asn1/der_encoder.c
	asn1/DestinationNumberCriteria.c
	asn1/DestinationNumberLengthList.c
	asn1/DestinationNumberList.c
	asn1/DGANSSExtensionSgnElement.c
	asn1/DGANSSExtensionSgnTypeElement.c
	asn1/DGANSSSgnElement.c
	asn1/DGPSCorrections.c
	asn1/DGPSCorrectionsValidityPeriod.c
	asn1/DGPSExtensionSatElement.c
	asn1/DiameterIdentity.c
	asn1/DispatcherList.c
	asn1/DomainType.c
	asn1/DP-AnalysedInfoCriteriaList.c
	asn1/DP-AnalysedInfoCriterium.c
	asn1/EctData.c
	asn1/EMLPP-Info.c
	asn1/EMLPP-Priority.c
	asn1/ENB-InterfaceList.c
	asn1/EncodingType.c
	asn1/EncryptionInformation.c
	asn1/EnvironmentCharacter.c
	asn1/EOTDQuality.c
	asn1/EPC-AV.c
	asn1/EphemerisSubframe1Reserved.c
	asn1/EPLMN-List.c
	asn1/EPS-AuthenticationSetList.c
	asn1/EPS-DataList.c
	asn1/EPS-Info.c
	asn1/EPS-QoS-Subscribed.c
	asn1/EPS-SubscriptionData.c
	asn1/EPS-SubscriptionDataWithdraw.c
	asn1/EquipmentStatus.c
	asn1/EraseCC-EntryArg.c
	asn1/EraseCC-EntryRes.c
	asn1/ErrorCodes.c
	asn1/E-UTRAN-CGI.c
	asn1/E-UTRAN-CGI-List.c
	asn1/EventThresholdRSRP.c
	asn1/EventThresholdRSRQ.c
	asn1/ExpectedOTD.c
	asn1/ExpOTDUncertainty.c
	asn1/Ext2-QoS-Subscribed.c
	asn1/Ext3-QoS-Subscribed.c
	asn1/Ext4-QoS-Subscribed.c
	asn1/Ext-BasicServiceCode.c
	asn1/Ext-BasicServiceGroupList.c
	asn1/Ext-BearerServiceCode.c
	asn1/Ext-CallBarFeatureList.c
	asn1/Ext-CallBarInfo.c
	asn1/Ext-CallBarringFeature.c
	asn1/Ext-CallBarringInfoFor-CSE.c
	asn1/Ext-CwFeature.c
	asn1/Ext-CwFeatureList.c
	asn1/Extended-reference.c
	asn1/ExtensibleCallBarredParam.c
	asn1/ExtensibleSystemFailureParam.c
	asn1/ExtensionContainer.c
	asn1/ExternalClient.c
	asn1/ExternalClientList.c
	asn1/ExternalSignalInfo.c
	asn1/Ext-ExternalClientList.c
	asn1/Ext-ExternalSignalInfo.c
	asn1/Ext-ForwardingInfoFor-CSE.c
	asn1/Ext-ForwFeature.c
	asn1/Ext-ForwFeatureList.c
	asn1/Ext-ForwInfo.c
	asn1/Ext-ForwOptions.c
	asn1/Ext-GeographicalInformation.c
	asn1/Ext-NoRepCondTime.c
	asn1/Ext-PDP-Type.c
	asn1/Ext-ProtocolId.c
	asn1/Ext-QoS-Subscribed.c
	asn1/Ext-SS-Data.c
	asn1/Ext-SS-Info.c
	asn1/Ext-SS-InfoFor-CSE.c
	asn1/Ext-SS-InfoList.c
	asn1/Ext-SS-Status.c
	asn1/Ext-TeleserviceCode.c
	asn1/FacilityNotSupParam.c
	asn1/FailureCause.c
	asn1/FailureCauseParam.c
	asn1/FailureReportArg.c
	asn1/FailureReportRes.c
	asn1/FineRTD.c
	asn1/FixType.c
	asn1/FormatIndicator.c
	asn1/ForwardAccessSignalling-Arg.c
	asn1/ForwardingFailedParam.c
	asn1/ForwardingFeature.c
	asn1/ForwardingFeatureList.c
	asn1/ForwardingInfo.c
	asn1/ForwardingOptions.c
	asn1/ForwardingViolationParam.c
	asn1/FQDN.c
	asn1/FQGWN.c
	asn1/FrameDrift.c
	asn1/FrameNumber.c
	asn1/FrequencyInfo.c
	asn1/FrequencyInfoFDD.c
	asn1/FrequencyInfoTDD.c
	asn1/FTN-AddressString.c
	asn1/GANSSAddIonosphericModel.c
	asn1/GANSSAdditionalAssistanceChoices.c
	asn1/GANSSAdditionalAssistanceChoicesForOneGANSS.c
	asn1/GANSSAddUTCModel.c
	asn1/GANSSAlmanacElement.c
	asn1/GANSSAlmanacModel.c
	asn1/GANSSAlmanacModel-R10-Ext.c
	asn1/GANSSAssistance.c
	asn1/GANSSAssistanceData.c
	asn1/GANSSAssistanceForOneGANSS.c
	asn1/GANSSAssistanceSet.c
	asn1/GANSS-AssistData.c
	asn1/GANSSAuxiliaryInformation.c
	asn1/GANSSClockModel.c
	asn1/GANSSCommonAssistData.c
	asn1/GANSS-ControlHeader.c
	asn1/GANSSDataBitAssist.c
	asn1/GANSSDataBit.c
	asn1/GanssDataBitsElement.c
	asn1/GANSSDataBitsSgnElement.c
	asn1/GANSSDeltaElementList.c
	asn1/GANSSDeltaEpochHeader.c
	asn1/GANSSDiffCorrections.c
	asn1/GANSSDiffCorrectionsValidityPeriod.c
	asn1/GANSSEarthOrientParam.c
	asn1/GANSSEphemerisDeltaBitSizes.c
	asn1/GANSSEphemerisDeltaEpoch.c
	asn1/GANSSEphemerisDeltaMatrix.c
	asn1/GANSSEphemerisDeltaScales.c
	asn1/GANSSEphemerisExtension.c
	asn1/GANSSEphemerisExtensionCheck.c
	asn1/GANSSEphemerisExtensionHeader.c
	asn1/GANSSEphemerisExtensionTime.c
	asn1/GANSSGenericAssistDataElement.c
	asn1/GANSS-ID1.c
	asn1/GANSS-ID1-element.c
	asn1/GANSS-ID3.c
	asn1/GANSS-ID3-element.c
	asn1/GANSSIonosphereModel.c
	asn1/GANSSIonosphericModel.c
	asn1/GANSSIonoStormFlags.c
	asn1/GANSSLocationInfo.c
	asn1/GANSSMeasureInfo.c
	asn1/GANSSModelID.c
	asn1/GANSS-MsrElement.c
	asn1/GANSS-MsrSetElement.c
	asn1/GANSSNavModel.c
	asn1/GANSSOrbitModel.c
	asn1/GANSSPositioningMethod.c
	asn1/GANSSPositioningMethodTypes.c
	asn1/GANSSPositionMethod.c
	asn1/GANSSPositionMethods.c
	asn1/GANSSRealTimeIntegrity.c
	asn1/GANSSReferenceOrbit.c
	asn1/GANSSReferenceTime.c
	asn1/GANSSReferenceTime-R10-Ext.c
	asn1/GANSSRefLocation.c
	asn1/GANSSRefMeasurementAssist.c
	asn1/GANSSRefMeasurementAssist-R10-Ext.c
	asn1/GANSSRefMeasurementElement.c
	asn1/GANSSRefMeasurement-R10-Ext-Element.c
	asn1/GANSSRefTimeInfo.c
	asn1/GANSSSatelliteElement.c
	asn1/GANSSSatEventsInfo.c
	asn1/GANSS-SgnElement.c
	asn1/GANSS-SgnTypeElement.c
	asn1/GANSSSignalID.c
	asn1/GANSSSignals.c
	asn1/GANSSTimeModelElement.c
	asn1/GANSSTimeModelElement-R10-Ext.c
	asn1/GANSSTOD.c
	asn1/GANSSTOD-GSMTimeAssociation.c
	asn1/GANSSTODm.c
	asn1/GANSSTODUncertainty.c
	asn1/GANSSUTCModel.c
	asn1/GeneralizedTime.c
	asn1/GenericServiceInfo.c
	asn1/GeodeticInformation.c
	asn1/GeographicalInformation.c
	asn1/GERAN-Classmark.c
	asn1/GeranGANSSpositioningData.c
	asn1/GGSN-EventList.c
	asn1/GGSN-InterfaceList.c
	asn1/GlobalCellId.c
	asn1/GLONASSclockModel.c
	asn1/GMLC-List.c
	asn1/GMLC-Restriction.c
	asn1/GPRS-CamelTDPData.c
	asn1/GPRS-CamelTDPDataList.c
	asn1/GPRSChargingID.c
	asn1/GPRS-CSI.c
	asn1/GPRSDataList.c
	asn1/GPRSMSClass.c
	asn1/GPRSSubscriptionData.c
	asn1/GPRSSubscriptionDataWithdraw.c
	asn1/GPRS-TriggerDetectionPoint.c
	asn1/GPSAcquisAssist-R10-Ext.c
	asn1/GPSAcquisAssist-R10-Ext-Element.c
	asn1/GPSAlmanac-R10-Ext.c
	asn1/GPSAssistance.c
	asn1/GPSAssistanceData.c
	asn1/GPS-AssistData.c
	asn1/GPSClockModel.c
	asn1/GPSDeltaElementList.c
	asn1/GPSDeltaEpochHeader.c
	asn1/GPSEphemerisDeltaBitSizes.c
	asn1/GPSEphemerisDeltaEpoch.c
	asn1/GPSEphemerisDeltaMatrix.c
	asn1/GPSEphemerisDeltaScales.c
	asn1/GPSEphemerisExtension.c
	asn1/GPSEphemerisExtensionCheck.c
	asn1/GPSEphemerisExtensionHeader.c
	asn1/GPSEphemerisExtensionTime.c
	asn1/GPS-MeasureInfo.c
	asn1/GPS-MsrElement.c
	asn1/GPS-MsrSetElement.c
	asn1/GPSReferenceOrbit.c
	asn1/GPSReferenceTime-R10-Ext.c
	asn1/GPSReferenceTimeUncertainty.c
	asn1/GPSSatEventsInfo.c
	asn1/GPSTimeAssistanceMeasurements.c
	asn1/GPSTime.c
	asn1/GPSTOW23b.c
	asn1/GPSTOW24b.c
	asn1/GPSTOWAssist.c
	asn1/GPSTOWAssistElement.c
	asn1/GPSWeek.c
	asn1/GroupId.c
	asn1/GsmCellInformation.c
	asn1/GSM-SecurityContextData.c
	asn1/GSMTime.c
	asn1/GSN-Address.c
	asn1/GuidanceInfo.c
	asn1/HLR-Id.c
	asn1/HLR-List.c
	asn1/HopCounter.c
	asn1/Horandveruncert.c
	asn1/Horandvervel.c
	asn1/Horizontal-Accuracy.c
	asn1/Horvel.c
	asn1/Horveluncert.c
	asn1/IA5String.c
	asn1/Identity.c
	asn1/IK.c
	asn1/IllegalEquipmentParam.c
	asn1/IllegalSS-OperationParam.c
	asn1/IllegalSubscriberParam.c
	asn1/IMEI.c
	asn1/IMSI.c
	asn1/IMSI-WithLMSI.c
	asn1/IMS-VoiceOverPS-SessionsInd.c
	asn1/IncompatibleTerminalParam.c
	asn1/InformationNotAvailableParam.c
	asn1/InformServiceCentreArg.c
	asn1/InsertSubscriberDataArg.c
	asn1/InsertSubscriberDataRes.c
	asn1/INTEGER.c
	asn1/IntegrityProtectionInformation.c
	asn1/InterCUG-Restrictions.c
	asn1/InterrogateSS-Res.c
	asn1/IntervalTime.c
	asn1/IntraCUG-Options.c
	asn1/IonosphericModel.c
	asn1/IPAddress.c
	asn1/IP-SM-GW-Guidance.c
	asn1/ISDN-AddressString.c
	asn1/ISDN-SubaddressString.c
	asn1/ISR-Information.c
	asn1/IST-AlertTimerValue.c
	asn1/IST-SupportIndicator.c
	asn1/JobType.c
	asn1/KASME.c
	asn1/Kc.c
	asn1/KeyIdentity2.c
	asn1/KeyIdentity3.c
	asn1/KeyIdentity4.c
	asn1/KeyIdentity.c
	asn1/KeyStatus.c
	asn1/KSI.c
	asn1/LAC.c
	asn1/LACSTR.c
	asn1/LAIFixedLength.c
	asn1/LCLS-ConfigurationPreference.c
	asn1/LCLS-GlobalCallReference.c
	asn1/LCLS-Negotiation.c
	asn1/LCSClientExternalID.c
	asn1/LCS-ClientID.c
	asn1/LCSClientInternalID.c
	asn1/LCSClientName.c
	asn1/LCSClientType.c
	asn1/LCSCodeword.c
	asn1/LCSCodewordString.c
	asn1/LCS-Event.c
	asn1/LCS-FormatIndicator.c
	asn1/LCSInformation.c
	asn1/LCSLocationInfo.c
	asn1/LCS-Priority.c
	asn1/LCS-PrivacyCheck.c
	asn1/LCS-PrivacyClass.c
	asn1/LCS-PrivacyExceptionList.c
	asn1/LCS-QoS.c
	asn1/LCS-ReferenceNumber.c
	asn1/LCSRequestorID.c
	asn1/LCSServiceTypeID.c
	asn1/LIPA-AllowedAPNList.c
	asn1/LIPA-Permission.c
	asn1/ListOfMeasurements.c
	asn1/LMSI.c
	asn1/LocationArea.c
	asn1/LocationAreaId-List.c
	asn1/LocationError.c
	asn1/LocationEstimateType.c
	asn1/LocationId.c
	asn1/LocationInfo.c
	asn1/LocationInformation.c
	asn1/LocationInformationEPS.c
	asn1/LocationInformationGPRS.c
	asn1/LocationInfoWithLMSI.c
	asn1/LocationNumber.c
	asn1/LocationType.c
	asn1/LocErrorReason.c
	asn1/LoggingDuration.c
	asn1/LoggingInterval.c
	asn1/Long-GroupId.c
	asn1/LongSignalInfo.c
	asn1/LongTermDenialParam.c
	asn1/LSAAttributes.c
	asn1/LSAData.c
	asn1/LSADataList.c
	asn1/LSAIdentity.c
	asn1/LSAIdentityList.c
	asn1/LSAInformation.c
	asn1/LSAInformationWithdraw.c
	asn1/LSAOnlyAccessIndicator.c
	asn1/MAC.c
	asn1/MatchType.c
	asn1/MaxMC-Bearers.c
	asn1/MC-Bearers.c
	asn1/M-CSI.c
	asn1/MC-SS-Info.c
	asn1/MDT-Configuration.c
	asn1/MeasuredResults.c
	asn1/MeasuredResultsList.c
	asn1/MeasureResponseTime.c
	asn1/MessageWaitListFullParam.c
	asn1/MethodType.c
	asn1/MG-CSI.c
	asn1/MGW-EventList.c
	asn1/MGW-InterfaceList.c
	asn1/MM-Code.c
	asn1/MME-EventList.c
	asn1/MME-InterfaceList.c
	asn1/MM-EventNotSupported-Param.c
	asn1/MNPInfoRes.c
	asn1/MobilityTriggers.c
	asn1/ModificationInstruction.c
	asn1/ModificationRequestFor-CB-Info.c
	asn1/ModificationRequestFor-CF-Info.c
	asn1/ModificationRequestFor-CH-Info.c
	asn1/ModificationRequestFor-CLIP-Info.c
	asn1/ModificationRequestFor-CLIR-Info.c
	asn1/ModificationRequestFor-CSG.c
	asn1/ModificationRequestFor-CSI.c
	asn1/ModificationRequestFor-CW-Info.c
	asn1/ModificationRequestFor-ECT-Info.c
	asn1/ModificationRequestFor-IP-SM-GW-Data.c
	asn1/ModificationRequestFor-ODB-data.c
	asn1/ModuloTimeSlot.c
	asn1/MO-ForwardSM-Arg.c
	asn1/MO-ForwardSM-Res.c
	asn1/MOLR-Class.c
	asn1/MOLR-List.c
	asn1/MoreAssDataToBeSent.c
	asn1/MpathIndic.c
	asn1/MS-Classmark2.c
	asn1/MSC-S-EventList.c
	asn1/MSC-S-InterfaceList.c
	asn1/MSISDN-BS.c
	asn1/MSISDN-BS-List.c
	asn1/MSNetworkCapability.c
	asn1/MSRadioAccessCapability.c
	asn1/MsrAssistBTS.c
	asn1/MsrAssistBTS-R98-ExpOTD.c
	asn1/MsrAssistData.c
	asn1/MsrAssistData-R98-ExpOTD.c
	asn1/MsrPosition-Req.c
	asn1/MsrPosition-Rsp.c
	asn1/MT-ForwardSM-Arg.c
	asn1/MT-ForwardSM-Res.c
	asn1/MT-ForwardSM-VGCS-Arg.c
	asn1/MT-ForwardSM-VGCS-Res.c
	asn1/MT-smsCAMELTDP-Criteria.c
	asn1/MT-smsCAMELTDP-CriteriaList.c
	asn1/MT-SMS-TPDU-Type.c
	asn1/MulticallBearerInfo.c
	asn1/MultiFrameCarrier.c
	asn1/MultiFrameOffset.c
	asn1/MultipleMeasurementSets.c
	asn1/MultipleSets.c
	asn1/MW-Status.c
	asn1/NAEA-CIC.c
	asn1/NAEA-PreferredCI.c
	asn1/NameString.c
	asn1/NativeEnumerated.c
	asn1/NativeInteger.c
	asn1/NAVclockModel.c
	asn1/NavigationModel.c
	asn1/NavModel-CNAVKeplerianSet.c
	asn1/NavModelElement.c
	asn1/NavModel-GLONASSecef.c
	asn1/NavModel-KeplerianSet.c
	asn1/NavModel-NAVKeplerianSet.c
	asn1/NavModel-SBASecef.c
	asn1/NeighborIdentity.c
	asn1/NetworkAccessMode.c
	asn1/NetworkResource.c
	asn1/NMR.c
	asn1/NMRelement.c
	asn1/NoGroupCallNbParam.c
	asn1/NonGANSSPositionMethods.c
	asn1/NoReplyConditionTime.c
	asn1/NoRoamingNbParam.c
	asn1/NoSubscriberReplyParam.c
	asn1/NoteMM-EventArg.c
	asn1/NoteMM-EventRes.c
	asn1/NoteMsPresentForGprsArg.c
	asn1/NoteMsPresentForGprsRes.c
	asn1/NoteSubscriberDataModifiedArg.c
	asn1/NoteSubscriberDataModifiedRes.c
	asn1/Notification.c
	asn1/NotificationToMSUser.c
	asn1/NotificationType.c
	asn1/NotReachableReason.c
	asn1/NSAPI.c
	asn1/NULL.c
	asn1/NumberChangedParam.c
	asn1/NumberOfRequestedVectors.c
	asn1/NumberPortabilityStatus.c
	asn1/NumericString.c
	asn1/NumOfMeasurements.c
	asn1/O-BcsmCamelTDP-Criteria.c
	asn1/O-BcsmCamelTDPCriteriaList.c
	asn1/O-BcsmCamelTDPData.c
	asn1/O-BcsmCamelTDPDataList.c
	asn1/O-BcsmTriggerDetectionPoint.c
	asn1/OBJECT_IDENTIFIER.c
	asn1/O-CauseValueCriteria.c
	asn1/OccurrenceInfo.c
	asn1/O-CSI.c
	asn1/OCTET_STRING.c
	asn1/ODB-Data.c
	asn1/ODB-GeneralData.c
	asn1/ODB-HPLMN-Data.c
	asn1/ODB-Info.c
	asn1/OfferedCamel4CSIs.c
	asn1/OfferedCamel4Functionalities.c
	asn1/OngoingGroupCallParam.c
	asn1/OR-NotAllowedParam.c
	asn1/OTD-FirstSetMsrs.c
	asn1/OTD-MeasureInfo-5-Ext.c
	asn1/OTD-MeasureInfo.c
	asn1/OTD-MeasureInfo-R98-Ext.c
	asn1/OTD-Measurement.c
	asn1/OTD-MeasurementWithID.c
	asn1/OTD-MsrElementFirst.c
	asn1/OTD-MsrElementFirst-R98-Ext.c
	asn1/OTD-MsrElementRest.c
	asn1/OTD-MsrsOfOtherSets.c
	asn1/OTDValue.c
	asn1/OverrideCategory.c
	asn1/PagingArea.c
	asn1/Password.c
	asn1/Pathloss.c
	asn1/PCS-Extensions.c
	asn1/PDN-GW-AllocationType.c
	asn1/PDN-GW-Identity.c
	asn1/PDN-GW-Update.c
	asn1/PDN-Type.c
	asn1/PDP-Address.c
	asn1/PDP-Context.c
	asn1/PDP-ContextInfo.c
	asn1/PDP-ContextInfoList.c
	asn1/PDP-Type.c
	asn1/per_decoder.c
	asn1/per_encoder.c
	asn1/PeriodicLDRInfo.c
	asn1/PermittedEncryptionAlgorithms.c
	asn1/PermittedIntegrityProtectionAlgorithms.c
	asn1/per_opentype.c
	asn1/per_support.c
	asn1/PGW-EventList.c
	asn1/PGW-InterfaceList.c
	asn1/PLMNClientList.c
	asn1/PLMN-Id.c
	asn1/PLMNList.c
	asn1/PosCapabilities.c
	asn1/PosCapability-Req.c
	asn1/PosCapability-Rsp.c
	asn1/Position.c
	asn1/PositionData.c
	asn1/PositionEstimate.c
	asn1/PositioningDataInformation.c
	asn1/PositionInstruct.c
	asn1/PositionMethod.c
	asn1/PositionMethodFailure-Diagnostic.c
	asn1/PositionMethodFailure-Param.c
	asn1/PosMethod.c
	asn1/PosPayLoad.c
	asn1/PosProtocol.c
	asn1/PosTechnology.c
	asn1/PrefMethod.c
	asn1/PrepareHO-Arg.c
	asn1/PrepareHO-Res.c
	asn1/PrepareSubsequentHO-Arg.c
	asn1/PrepareSubsequentHO-Res.c
	asn1/PrimaryCCPCH-RSCP.c
	asn1/PrimaryCPICH-Info.c
	asn1/PrivacyCheckRelatedAction.c
	asn1/PrivateExtension.c
	asn1/PrivateExtensionList.c
	asn1/ProcessAccessSignalling-Arg.c
	asn1/ProtocolError.c
	asn1/ProtocolId.c
	asn1/ProvideSubscriberInfoArg.c
	asn1/ProvideSubscriberInfoRes.c
	asn1/ProvideSubscriberLocation-Arg.c
	asn1/ProvideSubscriberLocation-Res.c
	asn1/PS-SubscriberState.c
	asn1/PurgeMS-Arg.c
	asn1/PurgeMS-Res.c
	asn1/PW-RegistrationFailureCause.c
	asn1/QoP.c
	asn1/QoS-Class-Identifier.c
	asn1/QoS-Subscribed.c
	asn1/QuintupletList.c
	asn1/RAB-Id.c
	asn1/RadioResource.c
	asn1/RadioResourceInformation.c
	asn1/RadioResourceList.c
	asn1/RAIdentity.c
	asn1/RANAP-ServiceHandover.c
	asn1/RAND.c
	asn1/RAN-Technology.c
	asn1/ReadyForSM-Arg.c
	asn1/ReadyForSM-Res.c
	asn1/ReferenceAssistData.c
	asn1/ReferenceFrame.c
	asn1/ReferenceIdentity.c
	asn1/ReferenceIdentityType.c
	asn1/ReferenceNavModel.c
	asn1/ReferenceRelation.c
	asn1/ReferenceTime.c
	asn1/ReferenceWGS84.c
	asn1/RefLocation.c
	asn1/RefQuality.c
	asn1/RegionalSubscriptionResponse.c
	asn1/RegisterCC-EntryArg.c
	asn1/RegisterCC-EntryRes.c
	asn1/RegisterSS-Arg.c
	asn1/Rel5-AssistanceData-Extension.c
	asn1/Rel5-MsrPosition-Req-Extension.c
	asn1/Rel-5-MsrPosition-Rsp-Extension.c
	asn1/Rel-5-ProtocolError-Extension.c
	asn1/Rel7-AssistanceData-Extension.c
	asn1/Rel7-MsrPosition-Req-Extension.c
	asn1/Rel-7-MsrPosition-Rsp-Extension.c
	asn1/Rel98-AssistanceData-Extension.c
	asn1/Rel98-Ext-ExpOTD.c
	asn1/Rel98-MsrPosition-Req-Extension.c
	asn1/Rel-98-MsrPosition-Rsp-Extension.c
	asn1/RelativeAlt.c
	asn1/RelDistance.c
	asn1/RelocationNumber.c
	asn1/RelocationNumberList.c
	asn1/ReportAmount.c
	asn1/ReportingAmount.c
	asn1/ReportingInterval.c
	asn1/ReportingPLMN.c
	asn1/ReportingPLMNList.c
	asn1/ReportingTrigger.c
	asn1/ReportInterval.c
	asn1/ReportSM-DeliveryStatusArg.c
	asn1/ReportSM-DeliveryStatusRes.c
	asn1/RequestedAssistData.c
	asn1/RequestedCAMEL-SubscriptionInfo.c
	asn1/RequestedEquipmentInfo.c
	asn1/RequestedInfo.c
	asn1/RequestedNodes.c
	asn1/RequestedServingNode.c
	asn1/RequestedSubscriptionInfo.c
	asn1/RequestIndex.c
	asn1/RequestingNodeType.c
	asn1/RequestorIDString.c
	asn1/RequiredResponseTime.c
	asn1/ResetArg.c
	asn1/ResourceLimitationParam.c
	asn1/ResponseTime.c
	asn1/ResponseTimeCategory.c
	asn1/RestoreDataArg.c
	asn1/RestoreDataRes.c
	asn1/Re-synchronisationInfo.c
	asn1/RFSP-ID.c
	asn1/RNCId.c
	asn1/RNC-InterfaceList.c
	asn1/RoamingNotAllowedCause.c
	asn1/RoamingNotAllowedParam.c
	asn1/RoughRTD.c
	asn1/RouteingNumber.c
	asn1/RoutingAreaId-List.c
	asn1/RoutingInfoForLCS-Arg.c
	asn1/RoutingInfoForLCS-Res.c
	asn1/RoutingInfoForSM-Arg.c
	asn1/RoutingInfoForSM-Res.c
	asn1/RRLP-Component.c
	asn1/RRLPNavigationModel.c
	asn1/RRLP-PDU.c
	asn1/SatElement.c
	asn1/SatelliteID.c
	asn1/SatelliteInfo.c
	asn1/SatelliteInfoElement.c
	asn1/SatStatus.c
	asn1/SBASclockModel.c
	asn1/SBASID.c
	asn1/SelectedGSM-Algorithm.c
	asn1/SelectedUMTS-Algorithms.c
	asn1/SendAuthenticationInfoArg.c
	asn1/SendAuthenticationInfoRes.c
	asn1/SendEndSignal-Arg.c
	asn1/SendEndSignal-Res.c
	asn1/SendIdentificationArg.c
	asn1/SendIdentificationRes.c
	asn1/SendRoutingInfoForGprsArg.c
	asn1/SendRoutingInfoForGprsRes.c
	asn1/SeqOfAcquisElement.c
	asn1/SeqOfAlmanacElement.c
	asn1/SeqOf-BadSatelliteSet.c
	asn1/SeqOfBadSignalElement.c
	asn1/SeqOfDGANSSExtensionSgnElement.c
	asn1/SeqOfDGANSSSgnElement.c
	asn1/SeqOfGANSSAlmanacElement.c
	asn1/SeqOf-GANSSDataBits.c
	asn1/SeqOfGanssDataBitsElement.c
	asn1/Seq-OfGANSSDataBitsSgn.c
	asn1/SeqOfGANSSGenericAssistDataElement.c
	asn1/SeqOfGANSS-MsrElement.c
	asn1/SeqOfGANSS-MsrSetElement.c
	asn1/SeqOfGANSSRefMeasurementElement.c
	asn1/SeqOfGANSSRefOrbit.c
	asn1/SeqOfGANSSSatelliteElement.c
	asn1/SeqOfGANSS-SgnElement.c
	asn1/SeqOfGANSS-SgnTypeElement.c
	asn1/SeqOfGANSSTimeModel.c
	asn1/SeqOfGANSSTimeModel-R10-Ext.c
	asn1/SeqOfGPS-MsrElement.c
	asn1/SeqOfGPS-MsrSetElement.c
	asn1/SeqOfGPSRefOrbit.c
	asn1/SeqOfMsrAssistBTS.c
	asn1/SeqOfMsrAssistBTS-R98-ExpOTD.c
	asn1/SeqOfNavModelElement.c
	asn1/SeqOfOTD-FirstSetMsrs.c
	asn1/SeqOfOTD-FirstSetMsrs-R98-Ext.c
	asn1/SeqOfOTD-MsrElementRest.c
	asn1/SeqOfOTD-MsrsOfOtherSets.c
	asn1/SeqOfReferenceIdentityType.c
	asn1/SeqOfSatElement.c
	asn1/SeqOfSgnTypeElement.c
	asn1/SeqOfStandardClockModelElement.c
	asn1/SeqOfSystemInfoAssistBTS.c
	asn1/SeqOfSystemInfoAssistBTS-R98-ExpOTD.c
	asn1/SequenceNumber.c
	asn1/ServiceIndicator.c
	asn1/ServiceKey.c
	asn1/ServiceType.c
	asn1/ServiceTypeList.c
	asn1/ServingNodeAddress.c
	asn1/ServingNode.c
	asn1/SessionID.c
	asn1/SETAuthKey.c
	asn1/SETCapabilities.c
	asn1/SETId.c
	asn1/SETNonce.c
	asn1/SetSessionID.c
	asn1/SgnTypeElement.c
	asn1/SGSN-CAMEL-SubscriptionInfo.c
	asn1/SGSN-Capability.c
	asn1/SGSN-EventList.c
	asn1/SGSN-InterfaceList.c
	asn1/SGW-EventList.c
	asn1/SGW-InterfaceList.c
	asn1/ShortTermDenialParam.c
	asn1/SignalInfo.c
	asn1/SIPTO-Permission.c
	asn1/SLPAddress.c
	asn1/SLPMode.c
	asn1/SlpSessionID.c
	asn1/SLR-ArgExtensionContainer.c
	asn1/SLR-Arg-PCS-Extensions.c
	asn1/SM-DeliveryFailureCause.c
	asn1/SM-DeliveryNotIntended.c
	asn1/SM-DeliveryOutcome.c
	asn1/SM-DeliveryTimerValue.c
	asn1/SM-EnumeratedDeliveryFailureCause.c
	asn1/SM-RP-DA.c
	asn1/SM-RP-MTI.c
	asn1/SM-RP-OA.c
	asn1/SM-RP-SMEA.c
	asn1/SMS-CAMEL-TDP-Data.c
	asn1/SMS-CAMEL-TDP-DataList.c
	asn1/SMS-CSI.c
	asn1/SMS-TriggerDetectionPoint.c
	asn1/SPCAuthKey.c
	asn1/SpecificAPNInfo.c
	asn1/SpecificAPNInfoList.c
	asn1/SpecificCSI-Withdraw.c
	asn1/SpecificGANSSAssistance.c
	asn1/SRES.c
	asn1/SS-CamelData.c
	asn1/SS-Code.c
	asn1/SS-CSI.c
	asn1/SS-Data.c
	asn1/SS-EventList.c
	asn1/SS-EventSpecification.c
	asn1/SS-ForBS-Code.c
	asn1/SS-IncompatibilityCause.c
	asn1/SS-Info.c
	asn1/SS-InfoList.c
	asn1/SS-InvocationNotificationArg.c
	asn1/SS-InvocationNotificationRes.c
	asn1/SS-List.c
	asn1/SS-NotAvailableParam.c
	asn1/SS-Status.c
	asn1/SS-SubscriptionOption.c
	asn1/SS-SubscriptionViolationParam.c
	asn1/StandardClockModelElement.c
	asn1/Status.c
	asn1/StatusCode.c
	asn1/StdResolution.c
	asn1/SubBusyForMT-SMS-Param.c
	asn1/SubscribedPeriodicLAUtimer.c
	asn1/SubscribedPeriodicRAUTAUtimer.c
	asn1/SubscriberData.c
	asn1/SubscriberId.c
	asn1/SubscriberIdentity.c
	asn1/SubscriberInfo.c
	asn1/SubscriberLocationReport-Arg.c
	asn1/SubscriberLocationReport-Res.c
	asn1/SubscriberState.c
	asn1/SubscriberStatus.c
	asn1/SuperChargerInfo.c
	asn1/SUPLAUTHREQ.c
	asn1/SUPLAUTHRESP.c
	asn1/SUPLEND.c
	asn1/SUPLINIT.c
	asn1/SUPLPOS.c
	asn1/SUPLPOSINIT.c
	asn1/SUPLRESPONSE.c
	asn1/SUPLSTART.c
	asn1/SupportedCamelPhases.c
	asn1/SupportedCodecsList.c
	asn1/SupportedFeatures.c
	asn1/SupportedGADShapes.c
	asn1/SupportedLCS-CapabilitySets.c
	asn1/SupportedRAT-Types.c
	asn1/SVID.c
	asn1/SystemFailureParam.c
	asn1/SystemInfoAssistBTS.c
	asn1/SystemInfoAssistBTS-R98-ExpOTD.c
	asn1/SystemInfoAssistData.c
	asn1/SystemInfoAssistData-R98-ExpOTD.c
	asn1/SystemInfoIndex.c
	asn1/TA0.c
	asn1/TA1.c
	asn1/TA2.c
	asn1/TA-Id.c
	asn1/TargetCellOutsideGCA-Param.c
	asn1/TBCD-STRING.c
	asn1/T-BCSM-CAMEL-TDP-Criteria.c
	asn1/T-BCSM-CAMEL-TDP-CriteriaList.c
	asn1/T-BcsmCamelTDPData.c
	asn1/T-BcsmCamelTDPDataList.c
	asn1/T-BcsmTriggerDetectionPoint.c
	asn1/T-CauseValueCriteria.c
	asn1/T-CSI.c
	asn1/TEID.c
	asn1/TeleserviceCode.c
	asn1/TeleserviceList.c
	asn1/TeleservNotProvParam.c
	asn1/TerminationCause.c
	asn1/TGSN.c
	asn1/Time.c
	asn1/TimeRelation.c
	asn1/TimeSlot.c
	asn1/TimeslotISCP.c
	asn1/TimeslotISCP-List.c
	asn1/TimeSlotScheme.c
	asn1/TLMReservedBits.c
	asn1/TLMWord.c
	asn1/TMSI.c
	asn1/TOA-MeasurementsOfRef.c
	asn1/TPDU-TypeCriterion.c
	asn1/TraceDepth.c
	asn1/TraceDepthList.c
	asn1/TraceEventList.c
	asn1/TraceInterfaceList.c
	asn1/TraceNE-TypeList.c
	asn1/TracePropagationList.c
	asn1/TraceRecordingSessionReference.c
	asn1/TraceReference2.c
	asn1/TraceReference.c
	asn1/TraceType.c
	asn1/TracingBufferFullParam.c
	asn1/TrackingAreaId-List.c
	asn1/TransactionId.c
	asn1/TripletList.c
	asn1/TypeOfUpdate.c
	asn1/UARFCN.c
	asn1/UESBI-IuA.c
	asn1/UESBI-IuB.c
	asn1/UESBI-Iu.c
	asn1/UE-SRVCC-Capability.c
	asn1/UlpMessage.c
	asn1/ULP-PDU.c
	asn1/UlPseudoSegInd.c
	asn1/UMTS-SecurityContextData.c
	asn1/UnauthorizedLCSClient-Diagnostic.c
	asn1/UnauthorizedLCSClient-Param.c
	asn1/UnauthorizedRequestingNetwork-Param.c
	asn1/UncompressedEphemeris.c
	asn1/UnexpectedDataParam.c
	asn1/UnidentifiedSubParam.c
	asn1/UnknownOrUnreachableLCSClient-Param.c
	asn1/UnknownSubscriberDiagnostic.c
	asn1/UnknownSubscriberParam.c
	asn1/UpdateGprsLocationArg.c
	asn1/UpdateGprsLocationRes.c
	asn1/UpdateLocationArg.c
	asn1/UpdateLocationRes.c
	asn1/Used-RAT-Type.c
	asn1/UseMultipleSets.c
	asn1/UserCSGInformation.c
	asn1/USSD-Arg.c
	asn1/USSD-DataCodingScheme.c
	asn1/USSD-Res.c
	asn1/USSD-String.c
	asn1/UTCModel.c
	asn1/UTCmodelSet2.c
	asn1/UTCmodelSet3.c
	asn1/UTCmodelSet4.c
	asn1/UTCTime.c
	asn1/UTRA-CarrierRSSI.c
	asn1/UtranGANSSpositioningData.c
	asn1/UtranPositioningDataInfo.c
	asn1/VBSDataList.c
	asn1/Velocity.c
	asn1/VelocityEstimate.c
	asn1/Ver.c
	asn1/Version.c
	asn1/Vertical-Accuracy.c
	asn1/VGCSDataList.c
	asn1/VisibleString.c
	asn1/VlrCamelSubscriptionInfo.c
	asn1/VLR-Capability.c
	asn1/VoiceBroadcastData.c
	asn1/VoiceGroupCallData.c
	asn1/WcdmaCellInformation.c
	asn1/WrongPasswordAttemptsCounter.c
	asn1/xer_decoder.c
	asn1/xer_encoder.c
	asn1/xer_support.c
	asn1/XRES.c
	asn1/ZoneCode.c
	asn1/ZoneCodeList.c
   }
  );


use ExtUtils::ParseXS;
use ExtUtils::Mkbootstrap;

sub ACTION_code {
    my $self = shift;

    # $self->dispatch("compile_asn1src");
    $self->dispatch("create_objects");
    # $self->dispatch("compile_swig");
    $self->dispatch("compile_xscode");

    $self->SUPER::ACTION_code;
}

sub compile_asn1src {
    #my $self = shift;

    #my $asn1_exe = IPC::Cmd->can_run( "asn1c" );
    #my @asn1_opt = qw(-gen-PER -fskeletons-copy -fnative-types -fcompound-names);
    #my @rrlp_src = qw(MAP-BS-Code.asn MAP-CommonDataTypes.asn MAP-ER-DataTypes.asn MAP-ExtensionDataTypes.asn MAP-LCS-DataTypes.asn MAP-MS-DataTypes.asn MAP-OM-DataTypes.asn MAP-SM-DataTypes.asn MAP-SS-Code.asn MAP-SS-DataTypes.asn MAP-TS-Code.asn RRLP-Components.asn RRLP-Messages.asn);
    #my @supl_src = qw(SUPL-AUTH-REQ.asn SUPL-AUTH-RESP.asn SUPL-END.asn SUPL-INIT.asn SUPL-POS.asn SUPL-POS-INIT.asn SUPL-RESPONSE.asn SUPL-START.asn ULP.asn ULP-Components.asn);
    #my @asn1_src = map { File::Spec->catfile( "../asn1src", $_ } @rrlp_src, @supl_src;
    #cd asn1
    #$self->execute_command( $asn1_exe, @asn1_opt, @asn1_src );
    #cd ..
}

sub ACTION_compile_swig {
    #my $self = shift;

    #my $swig_exe = IPC::Cmd->can_run( "swig" );
    #$self->execute_command( $swig_exe, "-Iasn1", "-perl", "SUPL_XS.swg" );
    #...
    # rename XS.pm => lib/SUPL/XS.pm
}

sub ACTION_compile_xscode {
    my $self = shift;
    my $cbuilder = $self->cbuilder;

    my $archdir = catdir( $self->blib, qw(arch auto Net Radio Location SUPL XS));
    mkpath( $archdir, 0, 0777 ) unless -d $archdir;

    print STDERR "\n** Preparing XS code\n";
    my $cfile = catfile("SUPL_XS_wrap.c");
    my $ofile = catfile("SUPL_XS_wrap.o");

    $self->add_to_cleanup($ofile); ## FIXME

    my $extra_compiler_flags = $self->notes('CFLAGS');
    $Config{ccflags} =~ /(-arch \S+(?: -arch \S+)*)/ and $extra_compiler_flags .= " $1";

    if (!$self->up_to_date($cfile, $ofile)) {
        $cbuilder->compile( source               => $cfile,
                            include_dirs         => [ catdir("asn1") ],
                            extra_compiler_flags => $extra_compiler_flags,
                            object_file          => $ofile);
    }

    # Create .bs bootstrap file, needed by Dynaloader.
    my $bs_file = catfile( $archdir, "XS.bs" );
    if ( !$self->up_to_date( $ofile, $bs_file ) ) {
        ExtUtils::Mkbootstrap::Mkbootstrap($bs_file);
        if ( !-f $bs_file ) {
            # Create file in case Mkbootstrap didn't do anything.
            open( my $fh, '>', $bs_file ) or confess "Can't open $bs_file: $!";
        }
        utime( (time) x 2, $bs_file );    # touch
    }

    my $o_files = $self->rscan_dir('asn1', qr/\.o$/);

    my $objects = [ $ofile, @$o_files ];
    # .o => .(a|bundle)
    my $lib_file = catfile( $archdir, "XS.$Config{dlext}" );
    if ( !$self->up_to_date( [ @$objects ], $lib_file ) ) {
        $cbuilder->link(
                        module_name => 'XS',
                        # extra_linker_flags => $extra_linker_flags,
                        objects     => $objects,
			lib_file    => $lib_file,
                       );
    }
}

sub ACTION_create_objects {
    my $self = shift;
    my $cbuilder = $self->cbuilder;

    print STDERR "\n** Compiling ASN.1 coder\n";

    my $extra_compiler_flags = $self->notes('CFLAGS');
    $Config{ccflags} =~ /(-arch \S+(?: -arch \S+)*)/ and $extra_compiler_flags .= " $1";

    for my $file (@SOURCES) {
        my $object = $file;
        $object =~ s/\.c/.o/;
        next if $self->up_to_date($file, $object);
        $cbuilder->compile(object_file  => $object,
                           source       => $file,
                           include_dirs => ["asn1"],
                           extra_compiler_flags => $extra_compiler_flags);
    }
}

