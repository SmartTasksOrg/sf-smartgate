"""A toy agent behind SmartGate: three tools, one approval, one kill. Run: python examples/python_agent.py"""
import threading
import time

from sf_smartgate import Blocked, Gate, Killed, checkpoint, impact_gate

gate = Gate()


@impact_gate(gate, action_type="read", agent_id="support-bot")
def look_up(order):
    return {"order": order, "amount": 2400}


@impact_gate(gate, action_type="api_call", agent_id="support-bot", cost=lambda order, amount: amount)
def refund(order, amount):
    for step in ("reserve", "transfer", "notify"):
        checkpoint()                      # a kill stops the refund between steps
        time.sleep(0.2)
    return f"refunded {amount} for {order}"


@impact_gate(gate, action_type="delete", agent_id="support-bot", reversible=False)
def delete_account(customer):
    return "deleted"


def operator():
    """Stands in for a person: approves the first pending request, then kills the refund."""
    time.sleep(0.3)
    for key, req in list(gate.store._d.items()):      # demo only: real operators use the API, CLI or Slack
        if key.startswith("approval:") and req["state"] == "pending":
            gate.approve(req["approval_id"], "demo-operator")
            time.sleep(0.3)
            print("operator:", gate.kill(req["action_id"], "changed my mind", "demo-operator"))


if __name__ == "__main__":
    print(look_up("A-1"))
    threading.Thread(target=operator).start()
    try:
        print(refund("A-1", 2400))
    except Killed as e:
        print("refund stopped:", e)
    try:
        delete_account("C-9")
    except Blocked as e:
        print("blocked:", e)
