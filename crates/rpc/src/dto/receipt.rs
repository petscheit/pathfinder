use super::serialize;
use crate::dto::serialize::SerializeForVersion;
use crate::dto::*;
use crate::RpcVersion;

#[derive(Copy, Clone)]
pub enum TxnStatus {
    Received,
    Rejected,
    AcceptedOnL2,
    AcceptedOnL1,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TxnExecutionStatus {
    Succeeded,
    Reverted,
}

impl From<&pathfinder_common::receipt::ExecutionStatus> for TxnExecutionStatus {
    fn from(value: &pathfinder_common::receipt::ExecutionStatus) -> Self {
        use pathfinder_common::receipt::ExecutionStatus;
        match value {
            ExecutionStatus::Succeeded => Self::Succeeded,
            ExecutionStatus::Reverted { .. } => Self::Reverted,
        }
    }
}

#[derive(Copy, Clone)]
pub enum TxnFinalityStatus {
    AcceptedOnL2,
    AcceptedOnL1,
}

impl SerializeForVersion for TxnStatus {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnStatus::Received => "RECEIVED",
            TxnStatus::Rejected => "REJECTED",
            TxnStatus::AcceptedOnL2 => "ACCEPTED_ON_L2",
            TxnStatus::AcceptedOnL1 => "ACCEPTED_ON_L1",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnExecutionStatus {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnExecutionStatus::Succeeded => "SUCCEEDED",
            TxnExecutionStatus::Reverted => "REVERTED",
        }
        .serialize(serializer)
    }
}

impl SerializeForVersion for TxnFinalityStatus {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        match self {
            TxnFinalityStatus::AcceptedOnL2 => "ACCEPTED_ON_L2",
            TxnFinalityStatus::AcceptedOnL1 => "ACCEPTED_ON_L1",
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions_sorted::assert_eq;
    use rstest::rstest;
    use serde_json::json;

    use super::*;
    use crate::dto::serialize::Serializer;

    #[rstest]
    #[case::received(TxnStatus::Received, "RECEIVED")]
    #[case::rejected(TxnStatus::Rejected, "REJECTED")]
    #[case::accepted_on_l2(TxnStatus::AcceptedOnL2, "ACCEPTED_ON_L2")]
    #[case::accepted_on_l1(TxnStatus::AcceptedOnL1, "ACCEPTED_ON_L1")]
    fn txn_status(#[case] input: TxnStatus, #[case] expected: &str) {
        let expected = json!(expected);
        let encoded = input.serialize(Serializer::default()).unwrap();
        assert_eq!(encoded, expected);
    }

    #[rstest]
    #[case::accepted_on_l2(TxnFinalityStatus::AcceptedOnL2, "ACCEPTED_ON_L2")]
    #[case::accepted_on_l1(TxnFinalityStatus::AcceptedOnL1, "ACCEPTED_ON_L1")]
    fn txn_finality_status(#[case] input: TxnFinalityStatus, #[case] expected: &str) {
        let expected = json!(expected);
        let encoded = input.serialize(Serializer::default()).unwrap();
        assert_eq!(encoded, expected);
    }

    #[rstest]
    #[case::accepted_on_l2(TxnExecutionStatus::Succeeded, "SUCCEEDED")]
    #[case::accepted_on_l1(TxnExecutionStatus::Reverted, "REVERTED")]
    fn txn_execution_status(#[case] input: TxnExecutionStatus, #[case] expected: &str) {
        let expected = json!(expected);
        let encoded = input.serialize(Serializer::default()).unwrap();
        assert_eq!(encoded, expected);
    }
}
