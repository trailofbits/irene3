//===- SkeletonEmitter.cpp - Skeleton TableGen backend          -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This Tablegen backend emits ...
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/DenseMapInfo.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/TableGen/TableGenBackend.h"

#include <glog/logging.h>
#include <llvm/TableGen/Main.h>
#include <llvm/TableGen/Record.h>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#define DEBUG_TYPE "skeleton-emitter"

namespace llvm
{
    class RecordKeeper;
    class raw_ostream;
} // namespace llvm

using namespace llvm;

namespace
{

    // Any helper data structures can be defined here. Some backends use
    // structs to collect information from the records.

    class IRENEEmitter {
      private:
        RecordKeeper &Records;

      public:
        IRENEEmitter(RecordKeeper &RK)
            : Records(RK) {}

        void emitType(raw_ostream &OS, Record *ty) {
            OS << "llvm::" << ty->getValueAsString("Namespace")
               << "::" << ty->getValueAsString("LLVMName");
        }

        bool run(raw_ostream &OS);
    }; // emitter class

} // anonymous namespace

bool IRENEEmitter::run(raw_ostream &OS) {
    emitSourceFileHeader("Target IRENE Mappings", OS);

    std::multimap< std::string, Record * > record_by_namespace;
    std::multimap< std::string, std::string > point_regs_by_namespace;
    std::multimap< std::string, std::string > stck_reg;
    std::unordered_set< std::string > namespaces;
    for (auto r : this->Records.getAllDerivedDefinitions("MappingRecord")) {
        auto spc = r->getValueAsString("namespace");
        namespaces.insert(spc.str());
        record_by_namespace.insert({ spc.str(), r });
    }

    for (auto r : this->Records.getAllDerivedDefinitions("PointerReg")) {
        auto spc = r->getValueAsString("namespace");
        namespaces.insert(spc.str());
        point_regs_by_namespace.insert({ spc.str(), r->getValueAsString("reg_name").str() });
    }

    for (auto r : this->Records.getAllDerivedDefinitions("StackRegister")) {
        auto spc = r->getValueAsString("namespace");
        namespaces.insert(spc.str());
        stck_reg.insert({ spc.str(), r->getValueAsString("reg_name").str() });
    }

    OS << "static const std::map<std::string,BackendInfo> BackendByName = {\n";

    for (auto k : namespaces) {
        OS << "\t{\"" << k << "\", BackendInfo {\n\t\t{\n";

        auto [rcit, rcend] = point_regs_by_namespace.equal_range(k);
        while (rcit != rcend) {
            OS << "\t\t\t\"" << rcit->second << "\",\n";
            rcit++;
        }
        OS << "\t\t},\n";

        auto [it, end] = record_by_namespace.equal_range(k);
        OS << "\t\t{\n";
        while (it != end) {
            auto r = it->second;
            OS << "\t\t\tInputMapping {\n";
            OS << "\t\t\t\t\"" << r->getValueAsString("from") << "\",\n";
            OS << "\t\t\t\t\"" << r->getValueAsString("to") << "\",\n";

            OS << "\t\t\t\t{\n";
            for (auto ty : r->getValueAsListOfDefs("applicable_types")) {
                OS << "\t\t\t\t\t";
                emitType(OS, ty);
                OS << ",\n";
            }
            OS << "\t\t\t\t},\n\t\t\t\t";
            emitType(OS, r->getValueAsDef("output"));
            OS << "\n\t\t\t},\n";
            it++;
        }
        OS << "\t\t}, ";

        if (stck_reg.contains(k)) {
            OS << "std::string(\"" << stck_reg.find(k)->second << "\")";
        } else {
            OS << "std::nullopt";
        }

        OS << "}\n\t},\n";
    }
    OS << "};\n";

    for (auto k : namespaces) {}

    return false;
}

//===----------------------------------------------------------------------===//
// Option B: Register "EmitSkeleton" directly
// The emitter entry may be private scope.
static bool EmitSkeleton(raw_ostream &OS, RecordKeeper &Records) {
    // Instantiate the emitter class and invoke run().
    IRENEEmitter(Records).run(OS);
    return false;
}

int main(int argc, char **argv) {
    google::InitGoogleLogging(argv[0]);
    cl::ParseCommandLineOptions(argc, argv);

    return llvm::TableGenMain(argv[0], EmitSkeleton);
}
