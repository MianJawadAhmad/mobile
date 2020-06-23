package app.covidshield.extensions

import app.covidshield.models.Configuration
import com.google.android.gms.nearby.exposurenotification.ExposureConfiguration

fun Configuration.toExposureConfiguration(): ExposureConfiguration {
//    return ExposureConfiguration.ExposureConfigurationBuilder()
//        .setMinimumRiskScore(minimumRiskScore)
//        .setAttenuationScores(*attenuationLevelValues.toIntArray())
//        .setAttenuationWeight(attenuationWeight)
//        .setDaysSinceLastExposureScores(*daysSinceLastExposureLevelValues.toIntArray())
//        .setDaysSinceLastExposureWeight(daysSinceLastExposureWeight)
//        .setDurationScores(*durationLevelValues.toIntArray())
//        .setDurationWeight(durationWeight)
//        .setTransmissionRiskScores(*transmissionRiskLevelValues.toIntArray())
//        .setTransmissionRiskWeight(transmissionRiskWeight)
//        .build()
    return ExposureConfiguration.ExposureConfigurationBuilder()
        .setDurationAtAttenuationThresholds(*listOf(50, 70).toIntArray())
        .setMinimumRiskScore(1)
        .setAttenuationScores(*listOf(0, 5, 5, 5, 5, 5, 5, 5).toIntArray())
        .setDaysSinceLastExposureScores(*listOf(1, 1, 1, 1, 1, 1, 1, 1).toIntArray())
        .setDurationScores(*listOf(0, 0, 0, 0, 5, 5, 5, 5).toIntArray())
        .setTransmissionRiskScores(*listOf(1, 1, 1, 1, 1, 1, 1, 1).toIntArray())
        .build()
}