package org.dependencytrack.vulndb.api;

import org.metaeffekt.core.security.cvss.CvssVector;
import org.metaeffekt.core.security.cvss.v2.Cvss2;
import org.metaeffekt.core.security.cvss.v3.Cvss3;
import org.metaeffekt.core.security.cvss.v4P0.Cvss4P0;

public record Rating(
        Method method,
        Severity severity,
        String vector,
        Double score) {

    public enum Method {
        CVSSv2,
        CVSSv3,
        CVSSv3_1,
        CVSSv4
    }

    public enum Severity {
        CRITICAL,
        LOW,
        HIGH,
        MEDIUM,
        INFO,
        NONE,
        UNKNOWN;

        public static Severity ofCvss(final CvssVector vector) {
            return switch (vector) {
                case Cvss2 cvss2 -> ofCvssV2Score(cvss2.getBaseScore());
                case Cvss3 cvss3 -> ofCvssV3Score(cvss3.getBaseScore());
                case Cvss4P0 cvss4 -> ofCvssV3Score(cvss4.getBaseScore());
                default -> throw new IllegalArgumentException("Unsupported CVSS vector: " + vector);
            };
        }

        private static Severity ofCvssV2Score(final double score) {
            if (score >= 7) {
                return Severity.HIGH;
            } else if (score >= 4) {
                return Severity.MEDIUM;
            } else if (score > 0) {
                return Severity.LOW;
            } else {
                return Severity.UNKNOWN;
            }
        }

        private static Severity ofCvssV3Score(final double score) {
            if (score >= 9) {
                return Severity.CRITICAL;
            } else if (score >= 7) {
                return Severity.HIGH;
            } else if (score >= 4) {
                return Severity.MEDIUM;
            } else if (score > 0) {
                return Severity.LOW;
            } else {
                return Severity.UNKNOWN;
            }
        }
    }

}
