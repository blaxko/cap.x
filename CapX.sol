// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/// @title CapX — On-chain spend enforcement for autonomous AI agent fleets
/// @notice An orchestrator agent creates a Policy with a global budget and
///         per-agent soft caps. Every payment a sub-agent wants to make must
///         clear checkAndDeduct() first. The deduction is atomic: it either
///         succeeds and the ledger updates, or it reverts entirely. There is
///         no code path where a sub-agent's spend is "provisionally" allowed
///         and cleaned up later — the cap is enforced by the EVM, not by
///         whichever application happens to be calling this contract.
/// @dev Deployed on X Layer (Chain ID 196). Gas paid in OKB.
contract CapX is AccessControl, ReentrancyGuard {
    bytes32 public constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    struct Policy {
        address orchestrator;
        uint256 globalBudget;
        uint256 spent;
        bool paused;
        bool exists;
    }

    struct AgentBudget {
        uint256 softCap;
        uint256 spent;
        bool active;
    }

    uint256 public nextPolicyId;

    mapping(uint256 => Policy) public policies;
    // policyId => agent address => budget
    mapping(uint256 => mapping(address => AgentBudget)) public agentBudgets;

    event PolicyCreated(uint256 indexed policyId, address indexed orchestrator, uint256 globalBudget);
    event AgentRegistered(uint256 indexed policyId, address indexed agent, uint256 softCap);
    event BudgetDeducted(uint256 indexed policyId, address indexed agent, uint256 amount, uint256 remainingGlobal, uint256 remainingAgent);
    event BudgetExceeded(uint256 indexed policyId, address indexed agent, uint256 attemptedAmount, string reason);
    event BudgetTopUp(uint256 indexed policyId, uint256 addedAmount, uint256 newGlobalBudget);
    event EmergencyPaused(uint256 indexed policyId, address indexed by);
    event PolicyResumed(uint256 indexed policyId, address indexed by);

    modifier onlyPolicyOrchestrator(uint256 policyId) {
        require(policies[policyId].exists, "CapX: policy does not exist");
        require(policies[policyId].orchestrator == msg.sender, "CapX: caller is not the policy orchestrator");
        _;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Create a new fleet spending policy.
    /// @param globalBudget Total budget available across all agents in this fleet, in wei.
    /// @param agents Initial list of sub-agent wallet addresses to register.
    /// @param softCaps Per-agent spend caps, in wei, matching the `agents` array by index.
    function createPolicy(
        uint256 globalBudget,
        address[] calldata agents,
        uint256[] calldata softCaps
    ) external returns (uint256 policyId) {
        require(globalBudget > 0, "CapX: globalBudget must be > 0");
        require(agents.length == softCaps.length, "CapX: agents/softCaps length mismatch");

        policyId = nextPolicyId++;

        policies[policyId] = Policy({
            orchestrator: msg.sender,
            globalBudget: globalBudget,
            spent: 0,
            paused: false,
            exists: true
        });

        _grantRole(ORCHESTRATOR_ROLE, msg.sender);

        for (uint256 i = 0; i < agents.length; i++) {
            _registerAgent(policyId, agents[i], softCaps[i]);
        }

        emit PolicyCreated(policyId, msg.sender, globalBudget);
    }

    /// @notice Register an additional agent under an existing policy.
    function registerAgent(uint256 policyId, address agent, uint256 softCap)
        external
        onlyPolicyOrchestrator(policyId)
    {
        _registerAgent(policyId, agent, softCap);
    }

    function _registerAgent(uint256 policyId, address agent, uint256 softCap) internal {
        require(agent != address(0), "CapX: agent cannot be zero address");
        agentBudgets[policyId][agent] = AgentBudget({softCap: softCap, spent: 0, active: true});
        emit AgentRegistered(policyId, agent, softCap);
    }

    /// @notice Atomically check and deduct a spend against both the agent's
    ///         soft cap and the fleet's global hard cap. Reverts entirely on
    ///         failure — there is no partial execution.
    /// @param policyId The policy this spend belongs to.
    /// @param agent The sub-agent attempting to spend.
    /// @param amount The amount, in wei, the agent wants to spend.
    function checkAndDeduct(uint256 policyId, address agent, uint256 amount)
        external
        nonReentrant
        returns (uint256 remainingGlobal, uint256 remainingAgent)
    {
        Policy storage policy = policies[policyId];
        require(policy.exists, "CapX: policy does not exist");
        require(!policy.paused, "CapX: policy is paused");

        AgentBudget storage budget = agentBudgets[policyId][agent];
        require(budget.active, "CapX: agent is not registered or active");

        if (budget.spent + amount > budget.softCap) {
            emit BudgetExceeded(policyId, agent, amount, "agent soft cap exceeded");
            revert("CapX: agent soft cap exceeded");
        }
        if (policy.spent + amount > policy.globalBudget) {
            emit BudgetExceeded(policyId, agent, amount, "global hard cap exceeded");
            revert("CapX: global hard cap exceeded");
        }

        budget.spent += amount;
        policy.spent += amount;

        remainingGlobal = policy.globalBudget - policy.spent;
        remainingAgent = budget.softCap - budget.spent;

        emit BudgetDeducted(policyId, agent, amount, remainingGlobal, remainingAgent);
    }

    /// @notice Instantly freeze all spending under a policy. Single transaction,
    ///         no per-agent calls required.
    function emergencyPause(uint256 policyId) external onlyPolicyOrchestrator(policyId) {
        policies[policyId].paused = true;
        emit EmergencyPaused(policyId, msg.sender);
    }

    /// @notice Resume a paused policy.
    function resumePolicy(uint256 policyId) external onlyPolicyOrchestrator(policyId) {
        policies[policyId].paused = false;
        emit PolicyResumed(policyId, msg.sender);
    }

    /// @notice Increase a policy's global budget mid-job.
    function topUpBudget(uint256 policyId, uint256 additionalAmount)
        external
        onlyPolicyOrchestrator(policyId)
    {
        require(additionalAmount > 0, "CapX: additionalAmount must be > 0");
        Policy storage policy = policies[policyId];
        policy.globalBudget += additionalAmount;
        emit BudgetTopUp(policyId, additionalAmount, policy.globalBudget);
    }

    /// @notice Remaining budget across the entire fleet for a policy.
    function remainingBudget(uint256 policyId) external view returns (uint256) {
        Policy storage policy = policies[policyId];
        require(policy.exists, "CapX: policy does not exist");
        return policy.globalBudget - policy.spent;
    }

    /// @notice Remaining budget for a single agent under a policy.
    function remainingAgentBudget(uint256 policyId, address agent) external view returns (uint256) {
        AgentBudget storage budget = agentBudgets[policyId][agent];
        require(budget.active, "CapX: agent is not registered or active");
        return budget.softCap - budget.spent;
    }
}
