from protocols.protocol import Protocol
from network import Network
from factory import ProtocolFactory

class Builder:
    @staticmethod
    def cast_value(original, new_value_str):
        """Cast input string to original data type."""
        try:
            if isinstance(original, int): return int(new_value_str)
            if isinstance(original, bool): return new_value_str.lower() in ("1", "true", "yes", "y")
        except: return new_value_str
        return new_value_str

    @staticmethod
    def edit_fields(structure: dict):
        """Display and edit dictionary fields."""
        print("\nAvailable fields:")
        for key, value in structure.items():
            print(f"  - {key}: {value}")
        field = input("\nWhich key to change (or Enter to skip)? ")
        if field in structure:
            val = input(f"Enter new value for '{field}': ")
            structure[field] = Builder.cast_value(structure[field], val)

    @staticmethod
    def build(root_protocol: Protocol, start_layer: Protocol = None):
        """Main loop to chain and edit protocols."""
        current_layer = start_layer if start_layer is not None else root_protocol

        if start_layer is None and hasattr(current_layer, 'setup'):
            current_layer.setup()

        while True:
            print(f"\n--- Editing Layer: {current_layer.name} ---")
            all_sub_dicts = {k: v for k, v in vars(current_layer).items() if isinstance(v, dict)}

            if all_sub_dicts:
                print("Parts:", list(all_sub_dicts.keys()))
                part = input("Which part to edit? ")
                if part in all_sub_dicts:
                    Builder.edit_fields(all_sub_dicts[part])

            add_payload = input(f"Add layer inside {current_layer.name}? (y/n) ")
            if add_payload.lower() == 'y':
                proto_name = input("Enter protocol name (e.g. UDP, IPv4): ")
                new_layer = ProtocolFactory.create(proto_name)
                if new_layer:
                    current_layer.payload = new_layer
                    current_layer = new_layer
                    if hasattr(current_layer, 'setup'):
                        current_layer.setup()
                    continue
            break

        if root_protocol.payload:
            print(f"DEBUG: Payload {root_protocol.payload.name} is attached.")

        print("\nSending packet...")
        ans = Network.send_and_received(root_protocol)
        print("Response:\n", ans)