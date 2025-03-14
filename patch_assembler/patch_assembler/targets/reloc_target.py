class RelocTarget:
    target_classes = []

    def __init__(self, p, binary_path):
        self.binary_path = binary_path
        self.p = p

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.target_classes.append(cls)

    @classmethod
    def detect_reloc_target(cls, binary_path):
        for target_class in cls.target_classes:
            if target_class.detect_target(binary_path):
                return target_class
        raise ValueError("Unknown target")
