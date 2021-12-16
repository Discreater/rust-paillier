
macro_rules! bigint {
    ( $t:ident, $body:item ) => {

        #[cfg(feature="inclramp")]
        mod ramp {
            #[allow(dead_code)]
            type $t = crate::RampBigInteger;
            $body
        }

        #[cfg(feature="inclgmp")]
        mod gmp {
            #[allow(dead_code)]
            type $t = crate::GmpBigInteger;
            $body
        }

        #[cfg(feature="inclnum")]
        mod num {
            #[allow(dead_code)]
            type $t = crate::NumBigInteger;
            $body
        }

    };
}
