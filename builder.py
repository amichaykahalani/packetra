from protocols.protocol import Protocol
from network import Network
from factory import ProtocolFactory
from style import Style


class Builder:
    @staticmethod
    def cast_value(original, new_value_str):
        """Cast input string to original data type."""
        try:
            if isinstance(original, int):
                return int(new_value_str)
            if isinstance(original, bool):
                return new_value_str.lower() in ("1", "true", "yes", "y")
        except:
            return new_value_str
        return new_value_str

    @staticmethod
    def _display_value(value):
        """Render bytes more readably: 6-byte values as MAC-style
        colon-hex, other byte strings as plain hex. Leaves everything
        else untouched."""
        if isinstance(value, bytes):
            if len(value) == 6:
                return ":".join(f"{b:02x}" for b in value)
            return value.hex()
        return value

    @staticmethod
    def edit_fields(structure: dict):
        """Display and edit dictionary fields. Loops until the user is
        done editing this part, so multiple fields can be changed in
        one visit instead of just one."""
        while True:
            print(Style.section("Available fields"))
            for key, value in structure.items():
                print(
                    f"  {Style.DIM}{key}{Style.RESET} = {Builder._display_value(value)}"
                )
            field = input(
                f"\n{Style.prompt('Which key to change (Enter to go back)? ')}"
            )
            if not field:
                return
            if field in structure:
                val = input(
                    f"  {Style.prompt(f'New value for ' + Style.BOLD + field + Style.RESET + ': ')}"
                )
                structure[field] = Builder.cast_value(structure[field], val)
            else:
                print(Style.error(f"'{field}' is not a valid field."))

    @staticmethod
    def build(root_protocol: Protocol, start_layer: Protocol = None):
        """Main loop to chain and edit protocols."""
        current_layer = start_layer if start_layer is not None else root_protocol

        if start_layer is None and hasattr(current_layer, "setup"):
            current_layer.setup()

        while True:
            print(Style.title(f"Editing Layer: {current_layer.name}"))
            all_sub_dicts = {
                k: v for k, v in vars(current_layer).items() if isinstance(v, dict)
            }

            # Loop here so the user can edit as many parts (and revisit
            # the same part more than once) as they want before moving
            # on, instead of being kicked to "Add layer?" after just one.
            while all_sub_dicts:
                print(Style.section("Parts"))
                for part_name in all_sub_dicts:
                    print(f"  {Style.DIM}-{Style.RESET} {part_name}")
                part = input(
                    f"\n{Style.prompt('Which part to edit (Enter to continue)? ')}"
                )
                if not part:
                    break
                if part in all_sub_dicts:
                    Builder.edit_fields(all_sub_dicts[part])
                else:
                    print(Style.error(f"'{part}' is not a valid part."))

            add_payload = input(
                f"\n{Style.prompt(f'Add layer inside {current_layer.name}? (y/n) ')}"
            )
            if add_payload.lower() == "y":
                proto_name = input(
                    f"  {Style.prompt('Enter protocol name (e.g. UDP, IPv4): ')}"
                )
                new_layer = ProtocolFactory.create(proto_name)
                if new_layer:
                    current_layer.payload = new_layer
                    current_layer = new_layer
                    if hasattr(current_layer, "setup"):
                        current_layer.setup()
                    continue
                else:
                    print(Style.error(f"Unknown protocol '{proto_name}'."))
            break

        if root_protocol.payload:
            print(
                Style.info(
                    f"\nLayer chain ready ({current_layer.name} attached as innermost payload)."
                )
            )

        print(Style.section("Sending packet"))
        ans = Network.send_and_received(root_protocol)
        print(f"{Style.success('Response:')}\n{ans}")
